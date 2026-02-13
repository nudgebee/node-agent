package common

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	lrucache "github.com/hashicorp/golang-lru/v2"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

const MAX_RESOLVED_DNS = 10000 // arbitrary limit
const MAX_PODS_LIMIT = 30000   // arbitrary limit

// MinimalPod holds only the essential fields from a v1.Pod object
// to reduce the memory footprint of the cache by ~90%.
type MinimalPod struct {
	UID             types.UID
	Name            string
	Namespace       string
	Labels          map[string]string
	NodeName        string
	PodIPs          []v1.PodIP
	OwnerReferences []metav1.OwnerReference
}

// MinimalOwnerInfo holds only OwnerReferences for resources in the owner chain
// (ReplicaSets, DaemonSets, StatefulSets, Jobs, Deployments, CronJobs).
type MinimalOwnerInfo struct {
	OwnerReferences []metav1.OwnerReference
}

type MinimalService struct {
	Name       string
	Namespace  string
	Selector   map[string]string
	ClusterIPs []string
}

type MinimalNode struct {
	Name      string
	Labels    map[string]string
	Addresses []v1.NodeAddress
}

type clusterSnapshot struct {
	Pods           sync.Map // map[types.UID]MinimalPod
	Nodes          sync.Map // map[types.UID]MinimalNode
	ReplicaSets    sync.Map // map[types.UID]MinimalOwnerInfo
	DaemonSets     sync.Map // map[types.UID]MinimalOwnerInfo
	StatefulSets   sync.Map // map[types.UID]MinimalOwnerInfo
	Jobs           sync.Map // map[types.UID]MinimalOwnerInfo
	Services       sync.Map // map[types.UID]MinimalService
	Deployments    sync.Map // map[types.UID]MinimalOwnerInfo
	CronJobs       sync.Map // map[types.UID]MinimalOwnerInfo
	PodDescriptors sync.Map // map[types.UID]Workload
	PodNameIndex   sync.Map // map["namespace/name"]types.UID
}

type K8sIPResolver struct {
	clientset        kubernetes.Interface
	snapshot         clusterSnapshot
	ipsMap           sync.Map
	stopSignal       chan struct{}
	shouldResolveDns bool
	dnsResolvedIps   *lrucache.Cache[string, string]
	podIpsMap        *lrucache.Cache[string, Workload]
	instanceMetaMap  sync.Map
}

type Workload struct {
	Name      string
	Namespace string
	Kind      string
	Region    string
	Zone      string
	Instance  string
}

type InstanceMeta struct {
	Region   string
	Zone     string
	Instance string
}

func NewK8sIPResolver(clientset kubernetes.Interface, resolveDns bool) (*K8sIPResolver, error) {
	var dnsCache *lrucache.Cache[string, string]
	var err error
	dnsCache, err = lrucache.New[string, string](MAX_RESOLVED_DNS)
	if err != nil {
		return nil, err
	}

	var podCache *lrucache.Cache[string, Workload]
	podCache, err = lrucache.New[string, Workload](MAX_PODS_LIMIT)
	if err != nil {
		return nil, err
	}

	return &K8sIPResolver{
		clientset:        clientset,
		snapshot:         clusterSnapshot{},
		ipsMap:           sync.Map{},
		stopSignal:       make(chan struct{}),
		shouldResolveDns: resolveDns,
		dnsResolvedIps:   dnsCache,
		podIpsMap:        podCache,
		instanceMetaMap:  sync.Map{},
	}, nil
}

func (resolver *K8sIPResolver) ResolveActualIP(ip string) Workload {
	if val, ok := resolver.podIpsMap.Get(ip); ok {
		return val
	}
	host := ip

	if resolver.shouldResolveDns {
		val, ok := resolver.dnsResolvedIps.Get(ip)
		if ok {
			host = val
		}
		// Note: Removed net.LookupAddr() - only use eBPF-captured DNS data for accuracy
	}
	return Workload{
		Name:      host,
		Namespace: "external",
		Kind:      "external",
		Zone:      "",
		Region:    "",
		Instance:  "",
	}
}

func (resolver *K8sIPResolver) ResolveIP(ip string) Workload {
	if val, ok := resolver.ipsMap.Load(ip); ok {
		entry, ok := val.(Workload)
		if ok {
			return entry
		}
		log.Printf("type confusion in ipsMap")
	}

	if val, ok := resolver.podIpsMap.Get(ip); ok {
		return val
	}
	host := ip

	if resolver.shouldResolveDns {
		val, ok := resolver.dnsResolvedIps.Get(ip)
		if ok {
			host = val
		}
		// Note: Removed net.LookupAddr() - only use eBPF-captured DNS data for accuracy
	}
	return Workload{
		Name:      host,
		Namespace: "external",
		Kind:      "external",
		Zone:      "",
		Region:    "",
		Instance:  "",
	}
}

func (resolver *K8sIPResolver) CacheDNS(ip string, dns string) Workload {
	resolver.dnsResolvedIps.Add(ip, dns)
	return Workload{
		Name:      dns,
		Namespace: "external",
		Kind:      "external",
		Zone:      "",
		Region:    "",
		Instance:  "",
	}
}

func (resolver *K8sIPResolver) StopWatching() {
	close(resolver.stopSignal)
}

func (resolver *K8sIPResolver) StartWatching() error {
	factory := informers.NewSharedInformerFactory(resolver.clientset, time.Minute*10)
	// Define individual informers
	podInformer := factory.Core().V1().Pods().Informer()
	nodeInformer := factory.Core().V1().Nodes().Informer()
	replicaSetInformer := factory.Apps().V1().ReplicaSets().Informer()
	daemonSetInformer := factory.Apps().V1().DaemonSets().Informer()
	statefulSetInformer := factory.Apps().V1().StatefulSets().Informer()
	jobInformer := factory.Batch().V1().Jobs().Informer()
	serviceInformer := factory.Core().V1().Services().Informer()
	deploymentInformer := factory.Apps().V1().Deployments().Informer()

	resolver.addPodHandlers(podInformer)
	resolver.addNodeHandlers(nodeInformer)
	resolver.addReplicaSetHandlers(replicaSetInformer)
	resolver.addDaemonSetHandlers(daemonSetInformer)
	resolver.addStatefulSetHandlers(statefulSetInformer)
	resolver.addJobHandlers(jobInformer)
	resolver.addServiceHandlers(serviceInformer)
	resolver.addDeploymentHandlers(deploymentInformer)

	// get initial state
	err := resolver.getResolvedClusterSnapshot()
	if err != nil {
		return fmt.Errorf("error retrieving cluster's initial state: %v", err)
	}
	factory.Start(resolver.stopSignal) // runs in background
	return nil
}

func (resolve *K8sIPResolver) addReplicaSetHandlers(replicaSetInformer cache.SharedIndexInformer) {
	replicaSetInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			rs := obj.(*appsv1.ReplicaSet)
			resolve.snapshot.ReplicaSets.Store(rs.UID, MinimalOwnerInfo{
				OwnerReferences: rs.OwnerReferences,
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			rs := newObj.(*appsv1.ReplicaSet)
			resolve.snapshot.ReplicaSets.Store(rs.UID, MinimalOwnerInfo{
				OwnerReferences: rs.OwnerReferences,
			})
		},
		DeleteFunc: func(obj interface{}) {
			rs := obj.(*appsv1.ReplicaSet)
			resolve.snapshot.ReplicaSets.Delete(rs.UID)
		},
	})
}

func (resolve *K8sIPResolver) addDaemonSetHandlers(daemonSetInformer cache.SharedIndexInformer) {
	daemonSetInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ds := obj.(*appsv1.DaemonSet)
			resolve.snapshot.DaemonSets.Store(ds.UID, MinimalOwnerInfo{
				OwnerReferences: ds.OwnerReferences,
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			ds := newObj.(*appsv1.DaemonSet)
			resolve.snapshot.DaemonSets.Store(ds.UID, MinimalOwnerInfo{
				OwnerReferences: ds.OwnerReferences,
			})
		},
		DeleteFunc: func(obj interface{}) {
			ds := obj.(*appsv1.DaemonSet)
			resolve.snapshot.DaemonSets.Delete(ds.UID)
		},
	})
}

func (resolve *K8sIPResolver) addStatefulSetHandlers(statefulSetInformer cache.SharedIndexInformer) {
	statefulSetInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ss := obj.(*appsv1.StatefulSet)
			resolve.snapshot.StatefulSets.Store(ss.UID, MinimalOwnerInfo{
				OwnerReferences: ss.OwnerReferences,
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			ss := newObj.(*appsv1.StatefulSet)
			resolve.snapshot.StatefulSets.Store(ss.UID, MinimalOwnerInfo{
				OwnerReferences: ss.OwnerReferences,
			})
		},
		DeleteFunc: func(obj interface{}) {
			ss := obj.(*appsv1.StatefulSet)
			resolve.snapshot.StatefulSets.Delete(ss.UID)
		},
	})
}

func (resolve *K8sIPResolver) addJobHandlers(jobInformer cache.SharedIndexInformer) {
	jobInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			job := obj.(*batchv1.Job)
			resolve.snapshot.Jobs.Store(job.UID, MinimalOwnerInfo{
				OwnerReferences: job.OwnerReferences,
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			job := newObj.(*batchv1.Job)
			resolve.snapshot.Jobs.Store(job.UID, MinimalOwnerInfo{
				OwnerReferences: job.OwnerReferences,
			})
		},
		DeleteFunc: func(obj interface{}) {
			job := obj.(*batchv1.Job)
			resolve.snapshot.Jobs.Delete(job.UID)
		},
	})
}

func (resolve *K8sIPResolver) addServiceHandlers(serviceInformer cache.SharedIndexInformer) {
	serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			service := obj.(*v1.Service)
			minSvc := MinimalService{
				Name:       service.Name,
				Namespace:  service.Namespace,
				Selector:   service.Spec.Selector,
				ClusterIPs: service.Spec.ClusterIPs,
			}
			resolve.snapshot.Services.Store(service.UID, minSvc)
			workload := resolve.resolveServiceWorkload(&minSvc)
			for _, clusterIp := range minSvc.ClusterIPs {
				if clusterIp != "None" {
					resolve.storeWorkloadsIP(clusterIp, &workload)
				}
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			service := newObj.(*v1.Service)
			minSvc := MinimalService{
				Name:       service.Name,
				Namespace:  service.Namespace,
				Selector:   service.Spec.Selector,
				ClusterIPs: service.Spec.ClusterIPs,
			}
			resolve.snapshot.Services.Store(service.UID, minSvc)
			workload := resolve.resolveServiceWorkload(&minSvc)
			for _, clusterIp := range minSvc.ClusterIPs {
				if clusterIp != "None" {
					resolve.storeWorkloadsIP(clusterIp, &workload)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			service := obj.(*v1.Service)
			resolve.snapshot.Services.Delete(service.UID)
			for _, clusterIp := range service.Spec.ClusterIPs {
				if clusterIp != "None" {
					resolve.ipsMap.Delete(clusterIp)
				}
			}
		},
	})
}

func (resolve *K8sIPResolver) addDeploymentHandlers(deploymentInformer cache.SharedIndexInformer) {
	deploymentInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			deployment := obj.(*appsv1.Deployment)
			resolve.snapshot.Deployments.Store(deployment.UID, MinimalOwnerInfo{
				OwnerReferences: deployment.OwnerReferences,
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			deployment := newObj.(*appsv1.Deployment)
			resolve.snapshot.Deployments.Store(deployment.UID, MinimalOwnerInfo{
				OwnerReferences: deployment.OwnerReferences,
			})
		},
		DeleteFunc: func(obj interface{}) {
			deployment := obj.(*appsv1.Deployment)
			resolve.snapshot.Deployments.Delete(deployment.UID)
		},
	})
}

func (resolver *K8sIPResolver) addPodHandlers(podInformer cache.SharedIndexInformer) {
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)
			resolver.handlePodAdd(pod)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newPod := newObj.(*v1.Pod)
			resolver.handlePodAdd(newPod)
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)
			resolver.snapshot.Pods.Delete(pod.UID)
			resolver.snapshot.PodDescriptors.Delete(pod.UID)
			resolver.snapshot.PodNameIndex.Delete(pod.Namespace + "/" + pod.Name)
			for _, podIp := range pod.Status.PodIPs {
				resolver.podIpsMap.Remove(podIp.IP)
			}
		},
	})
}

func (resolver *K8sIPResolver) handlePodAdd(pod *v1.Pod) bool {
	minPod := MinimalPod{
		UID:             pod.UID,
		Name:            pod.Name,
		Namespace:       pod.Namespace,
		Labels:          pod.Labels,
		NodeName:        pod.Spec.NodeName,
		PodIPs:          pod.Status.PodIPs,
		OwnerReferences: pod.ObjectMeta.OwnerReferences,
	}
	resolver.snapshot.Pods.Store(pod.UID, minPod)
	resolver.snapshot.PodNameIndex.Store(pod.Namespace+"/"+pod.Name, pod.UID)
	entry := resolver.resolvePodDescriptor(&minPod)
	instanceMeta, ok := resolver.instanceMetaMap.Load(pod.Spec.NodeName)
	region := ""
	zone := ""
	if ok {
		instanceMeta, ok := instanceMeta.(InstanceMeta)
		if ok {
			region = instanceMeta.Region
			zone = instanceMeta.Zone
		} else {
			klog.V(5).Infof("type confusion in instance meta for node %s", pod.Spec.NodeName)
		}
	}
	for _, podIp := range pod.Status.PodIPs {
		resolver.storeWorkloadsIP(podIp.IP, &entry)
		podWorkload := Workload{
			Name:      pod.Name,
			Namespace: pod.Namespace,
			Kind:      "pod",
			Region:    region,
			Zone:      zone,
			Instance:  pod.Spec.NodeName,
		}
		resolver.storePodsIP(podIp.IP, &podWorkload)
	}
	return false
}

func (resolver *K8sIPResolver) addNodeHandlers(nodeInformer cache.SharedIndexInformer) {
	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*v1.Node)
			shouldReturn := resolver.handleNodeEvent(node)
			if shouldReturn {
				return
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			node := newObj.(*v1.Node)
			shouldReturn := resolver.handleNodeEvent(node)
			if shouldReturn {
				return
			}
		},
		DeleteFunc: func(obj interface{}) {
			node := obj.(*v1.Node)
			resolver.snapshot.Nodes.Delete(node.UID)
			resolver.instanceMetaMap.Delete(node.Name)
		},
	})
}

func (resolver *K8sIPResolver) handleNodeEvent(node *v1.Node) bool {
	resolver.snapshot.Nodes.Store(node.UID, MinimalNode{
		Name:      node.Name,
		Labels:    node.Labels,
		Addresses: node.Status.Addresses,
	})
	region := node.Labels["topology.kubernetes.io/region"]
	zone := node.Labels["topology.kubernetes.io/zone"]
	meta := InstanceMeta{
		Region:   region,
		Zone:     zone,
		Instance: node.Name,
	}
	resolver.instanceMetaMap.Store(node.Name, meta)
	for _, nodeAddress := range node.Status.Addresses {
		resolver.storeWorkloadsIP(nodeAddress.Address, &Workload{
			Name:      node.Name,
			Namespace: "node",
			Kind:      "node",
			Region:    region,
			Zone:      zone,
			Instance:  node.Name,
		})
	}
	return false
}

func (resolver *K8sIPResolver) getResolvedClusterSnapshot() error {
	log.Printf("Generating full cluster snapshot")
	err := resolver.getFullClusterSnapshot()
	if err != nil {
		return err
	}
	resolver.updateIpMapping()
	log.Printf("Generated full cluster snapshot")
	return nil
}

// iterate the API for initial coverage of the cluster's state
func (resolver *K8sIPResolver) getFullClusterSnapshot() error {
	pods, err := resolver.clientset.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return errors.New("error getting pods, aborting snapshot update")
	}
	log.Printf("loaded pods data %d", pods.Size())

	for _, pod := range pods.Items {
		minPod := MinimalPod{
			UID:             pod.UID,
			Name:            pod.Name,
			Namespace:       pod.Namespace,
			Labels:          pod.Labels,
			NodeName:        pod.Spec.NodeName,
			PodIPs:          pod.Status.PodIPs,
			OwnerReferences: pod.ObjectMeta.OwnerReferences,
		}
		resolver.snapshot.Pods.Store(pod.UID, minPod)
		resolver.snapshot.PodNameIndex.Store(pod.Namespace+"/"+pod.Name, pod.UID)
	}

	nodes, err := resolver.clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return errors.New("error getting nodes, aborting snapshot update")
	}
	for _, node := range nodes.Items {
		// extract region and zone from attributes
		region := node.Labels["topology.kubernetes.io/region"]
		zone := node.Labels["topology.kubernetes.io/zone"]
		meta := InstanceMeta{
			Region: region,
			Zone:   zone,
		}
		resolver.instanceMetaMap.Store(node.Name, meta)
		resolver.snapshot.Nodes.Store(node.UID, MinimalNode{
			Name:      node.Name,
			Labels:    node.Labels,
			Addresses: node.Status.Addresses,
		})
	}

	replicasets, err := resolver.clientset.AppsV1().ReplicaSets("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return errors.New("error getting replicasets, aborting snapshot update")
	}
	for _, rs := range replicasets.Items {
		resolver.snapshot.ReplicaSets.Store(rs.ObjectMeta.UID, MinimalOwnerInfo{
			OwnerReferences: rs.OwnerReferences,
		})
	}

	daemonsets, err := resolver.clientset.AppsV1().DaemonSets("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return errors.New("error getting daemonsets, aborting snapshot update")
	}
	for _, ds := range daemonsets.Items {
		resolver.snapshot.DaemonSets.Store(ds.ObjectMeta.UID, MinimalOwnerInfo{
			OwnerReferences: ds.OwnerReferences,
		})
	}

	statefulsets, err := resolver.clientset.AppsV1().StatefulSets("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return errors.New("error getting statefulsets, aborting snapshot update")
	}
	for _, ss := range statefulsets.Items {
		resolver.snapshot.StatefulSets.Store(ss.ObjectMeta.UID, MinimalOwnerInfo{
			OwnerReferences: ss.OwnerReferences,
		})
	}

	jobs, err := resolver.clientset.BatchV1().Jobs("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return errors.New("error getting jobs, aborting snapshot update")
	}
	for _, job := range jobs.Items {
		resolver.snapshot.Jobs.Store(job.ObjectMeta.UID, MinimalOwnerInfo{
			OwnerReferences: job.OwnerReferences,
		})
	}

	services, err := resolver.clientset.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return errors.New("error getting services, aborting snapshot update")
	}
	for _, service := range services.Items {
		resolver.snapshot.Services.Store(service.UID, MinimalService{
			Name:       service.Name,
			Namespace:  service.Namespace,
			Selector:   service.Spec.Selector,
			ClusterIPs: service.Spec.ClusterIPs,
		})
	}

	deployments, err := resolver.clientset.AppsV1().Deployments("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return errors.New("error getting deployments, aborting snapshot update")
	}
	for _, deployment := range deployments.Items {
		resolver.snapshot.Deployments.Store(deployment.UID, MinimalOwnerInfo{
			OwnerReferences: deployment.OwnerReferences,
		})
	}

	cronJobs, err := resolver.clientset.BatchV1().CronJobs("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		cronJobs, err := resolver.clientset.BatchV1beta1().CronJobs("").List(context.Background(), metav1.ListOptions{})
		if err != nil {
			return errors.New("error getting cronjobs, aborting snapshot update")
		}
		for _, cronJob := range cronJobs.Items {
			resolver.snapshot.CronJobs.Store(cronJob.UID, MinimalOwnerInfo{
				OwnerReferences: cronJob.OwnerReferences,
			})
		}
	}
	for _, cronJob := range cronJobs.Items {
		resolver.snapshot.CronJobs.Store(cronJob.UID, MinimalOwnerInfo{
			OwnerReferences: cronJob.OwnerReferences,
		})
	}

	return nil
}

// add mapping from ip to resolved host to an existing map,
// based on the given cluster snapshot
func (resolver *K8sIPResolver) updateIpMapping() {
	// because IP collisions may occur and lead to overwrites in the map, the order is important
	// we go from less "favorable" to more "favorable" -
	// services -> running pods -> nodes

	resolver.snapshot.Services.Range(func(key any, val any) bool {
		svc, ok := val.(MinimalService)
		if !ok {
			log.Printf("Type confusion in services map")
			return true // continue
		}
		workload := resolver.resolveServiceWorkload(&svc)
		for _, clusterIp := range svc.ClusterIPs {
			if clusterIp != "None" {
				resolver.storeWorkloadsIP(clusterIp, &workload)
			}
		}
		return true
	})

	resolver.snapshot.Nodes.Range(func(key any, value any) bool {
		node, ok := value.(MinimalNode)
		if !ok {
			log.Printf("Type confusion in nodes map")
			return true // continue
		}
		for _, nodeAddress := range node.Addresses {
			// extract region and zone from attributes
			region := node.Labels["topology.kubernetes.io/region"]
			zone := node.Labels["topology.kubernetes.io/zone"]
			meta := InstanceMeta{
				Region:   region,
				Zone:     zone,
				Instance: node.Name,
			}
			resolver.instanceMetaMap.Store(node.Name, meta)
			workload := Workload{
				Name:      node.Name,
				Namespace: "node",
				Kind:      "node",
				Region:    region,
				Zone:      zone,
				Instance:  node.Name,
			}
			resolver.storeWorkloadsIP(nodeAddress.Address, &workload)
		}
		return true
	})

	resolver.snapshot.Pods.Range(func(key, value any) bool {
		pod, ok := value.(MinimalPod)
		if !ok {
			log.Printf("Type confusion in pods map")
			return true // continue
		}
		entry := resolver.resolvePodDescriptor(&pod)
		for _, podIp := range pod.PodIPs {
			// if ip is already in the map, override only if current pod is running
			resolver.storeWorkloadsIP(podIp.IP, &entry)
			instanceMeta, ok := resolver.instanceMetaMap.Load(pod.NodeName)
			region := ""
			zone := ""
			if ok {
				instanceMeta, ok := instanceMeta.(InstanceMeta)
				if ok {
					region = instanceMeta.Region
					zone = instanceMeta.Zone
				} else {
					klog.V(5).Infof("type confusion in instance meta for node %s", pod.NodeName)
				}
			} else {
				log.Printf("Missing instance meta for node %s", pod.NodeName)
			}
			podWorkload := Workload{
				Name:      pod.Name,
				Namespace: pod.Namespace,
				Kind:      "pod",
				Region:    region,
				Zone:      zone,
				Instance:  pod.NodeName,
			}
			resolver.storePodsIP(podIp.IP, &podWorkload)
		}
		return true
	})
}

func (resolver *K8sIPResolver) storeWorkloadsIP(ip string, newWorkload *Workload) {
	// we want to override existing workload, unless the existing workload is a node and the new one isn't
	val, ok := resolver.ipsMap.Load(ip)
	if ok {
		existingWorkload, ok := val.(Workload)
		if ok {
			if existingWorkload.Kind == "node" && newWorkload.Kind != "node" {
				return
			}
		}
	}
	resolver.ipsMap.Store(ip, *newWorkload)
}

func (resolver *K8sIPResolver) storePodsIP(ip string, newWorkload *Workload) {
	resolver.podIpsMap.Add(ip, *newWorkload)
}

func (resolver *K8sIPResolver) resolveServiceWorkload(svc *MinimalService) Workload {
	workload := Workload{
		Name:      svc.Name,
		Namespace: svc.Namespace,
		Kind:      "Service",
	}
	if len(svc.Selector) == 0 {
		return workload
	}
	resolver.snapshot.Pods.Range(func(key any, value any) bool {
		pod, ok := value.(MinimalPod)
		if !ok || pod.Namespace != svc.Namespace || pod.Labels == nil {
			return true // continue
		}
		if labelsMatch(pod.Labels, svc.Selector) {
			owner := resolver.ResolvePodOwner(pod.Name, pod.Namespace)
			workload.Name = owner.Name
			workload.Kind = owner.Kind
			workload.Region = owner.Region
			workload.Zone = owner.Zone
			return false // stop iteration
		}
		return true // continue
	})
	return workload
}

func labelsMatch(labels, selector map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func getControllerOwnerRef(refs []metav1.OwnerReference) *metav1.OwnerReference {
	for i := range refs {
		if refs[i].Controller != nil && *refs[i].Controller {
			ref := refs[i]
			return &ref
		}
	}
	return nil
}

func (resolver *K8sIPResolver) getControllerOfOwner(owner *metav1.OwnerReference) (*metav1.OwnerReference, error) {
	var m *sync.Map
	switch owner.Kind {
	case "ReplicaSet":
		m = &resolver.snapshot.ReplicaSets
	case "DaemonSet":
		m = &resolver.snapshot.DaemonSets
	case "StatefulSet":
		m = &resolver.snapshot.StatefulSets
	case "Job":
		m = &resolver.snapshot.Jobs
	case "Deployment":
		m = &resolver.snapshot.Deployments
	case "CronJob":
		m = &resolver.snapshot.CronJobs
	default:
		return nil, fmt.Errorf("unsupported kind: %s", owner.Kind)
	}
	val, ok := m.Load(owner.UID)
	if !ok {
		return nil, fmt.Errorf("missing %s for UID %s", owner.Kind, owner.UID)
	}
	info := val.(MinimalOwnerInfo)
	return getControllerOwnerRef(info.OwnerReferences), nil
}

func (resolver *K8sIPResolver) resolvePodDescriptor(pod *MinimalPod) Workload {
	existing, ok := resolver.snapshot.PodDescriptors.Load(pod.UID)
	if ok {
		result, ok := existing.(Workload)
		if ok {
			return result
		}
	}
	var err error
	name := pod.Name
	namespace := pod.Namespace
	kind := "pod"

	// Resolve owner hierarchy using OwnerReferences from MinimalPod
	if len(pod.OwnerReferences) > 0 {
		// Find the controller owner reference
		for _, owner := range pod.OwnerReferences {
			if owner.Controller != nil && *owner.Controller {
				name = owner.Name
				kind = owner.Kind
				// Try to climb up the ownership hierarchy
				if owner, err := resolver.getControllerOfOwner(&owner); err == nil && owner != nil {
					for owner != nil {
						name = owner.Name
						kind = owner.Kind
						owner, err = resolver.getControllerOfOwner(owner)
						if err != nil {
							klog.V(5).Infof("couldn't retrieve owner of %v - %v", name, err)
							break
						}
					}
				}
				break
			}
		}
	}

	instanceMeta, ok := resolver.instanceMetaMap.Load(pod.NodeName)
	region := ""
	zone := ""
	if ok {
		instanceMeta, ok := instanceMeta.(InstanceMeta)
		if ok {
			region = instanceMeta.Region
			zone = instanceMeta.Zone
		} else {
			klog.V(5).Infof("type confusion in instance meta for node %s", pod.NodeName)
		}
	} else {
		klog.V(5).Infof("missing instance meta for node %s", pod.NodeName)
		if klog.V(5).Enabled() {
			resolver.instanceMetaMap.Range(func(key, value interface{}) bool {
				klog.V(5).Infof("instance meta key: %s, value: %v", key, value)
				return true
			})
		}
	}
	result := Workload{
		Name:      name,
		Namespace: namespace,
		Kind:      kind,
		Region:    region,
		Zone:      zone,
		Instance:  pod.NodeName,
	}
	if err == nil {
		resolver.snapshot.PodDescriptors.Store(pod.UID, result)
	}
	return result
}

func (resolver *K8sIPResolver) ResolvePodOwner(podName string, podNamespace string) Workload {
	if uidVal, ok := resolver.snapshot.PodNameIndex.Load(podNamespace + "/" + podName); ok {
		if podVal, ok := resolver.snapshot.Pods.Load(uidVal.(types.UID)); ok {
			pod := podVal.(MinimalPod)
			return resolver.resolvePodDescriptor(&pod)
		}
	}

	// Fallback to API server if not in cache (should be rare)
	pods, err := resolver.clientset.CoreV1().Pods(podNamespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		return Workload{
			Name:      podName,
			Namespace: podNamespace,
			Kind:      "Pod",
			Region:    "",
			Zone:      "",
			Instance:  "",
		}
	}
	minPod := &MinimalPod{
		UID:             pods.UID,
		Name:            pods.Name,
		Namespace:       pods.Namespace,
		Labels:          pods.Labels,
		NodeName:        pods.Spec.NodeName,
		PodIPs:          pods.Status.PodIPs,
		OwnerReferences: pods.ObjectMeta.OwnerReferences,
	}
	return resolver.resolvePodDescriptor(minPod)
}
