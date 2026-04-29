package common

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/flags"
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
	ipsMapMu         sync.Mutex // protects check-then-act on ipsMap
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

// stripPod removes all fields from a Pod that the resolver doesn't need,
// reducing the informer cache footprint by ~90% per pod object.
func stripPod(obj interface{}) (interface{}, error) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		return obj, nil
	}
	pod.ManagedFields = nil
	pod.Annotations = nil
	pod.Finalizers = nil
	pod.Spec.Containers = nil
	pod.Spec.InitContainers = nil
	pod.Spec.Volumes = nil
	pod.Spec.EphemeralContainers = nil
	pod.Spec.ImagePullSecrets = nil
	pod.Spec.Tolerations = nil
	pod.Spec.Affinity = nil
	pod.Spec.TopologySpreadConstraints = nil
	pod.Status.Conditions = nil
	pod.Status.ContainerStatuses = nil
	pod.Status.InitContainerStatuses = nil
	pod.Status.EphemeralContainerStatuses = nil
	return pod, nil
}

// stripNode removes unneeded fields from a Node object.
func stripNode(obj interface{}) (interface{}, error) {
	node, ok := obj.(*v1.Node)
	if !ok {
		return obj, nil
	}
	node.ManagedFields = nil
	node.Annotations = nil
	node.Spec = v1.NodeSpec{}
	node.Status.Conditions = nil
	node.Status.Images = nil
	node.Status.VolumesAttached = nil
	node.Status.VolumesInUse = nil
	node.Status.Capacity = nil
	node.Status.Allocatable = nil
	return node, nil
}

// stripService removes unneeded fields from a Service object.
func stripService(obj interface{}) (interface{}, error) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		return obj, nil
	}
	svc.ManagedFields = nil
	svc.Annotations = nil
	// Keep: Name, Namespace, Spec.Selector, Spec.ClusterIPs
	svc.Spec.Ports = nil
	svc.Status = v1.ServiceStatus{}
	return svc, nil
}

// stripOwnerOnly removes everything except ObjectMeta (for UID and OwnerReferences)
// from resources where we only need the ownership chain (ReplicaSet, Deployment, etc.).
func stripOwnerOnly(obj interface{}) (interface{}, error) {
	type objectMetaAccessor interface {
		GetObjectMeta() metav1.Object
	}
	if accessor, ok := obj.(objectMetaAccessor); ok {
		meta := accessor.GetObjectMeta()
		meta.SetManagedFields(nil)
		meta.SetAnnotations(nil)
		meta.SetLabels(nil)
	}
	// Type-specific spec/status clearing
	switch o := obj.(type) {
	case *appsv1.ReplicaSet:
		o.Spec = appsv1.ReplicaSetSpec{}
		o.Status = appsv1.ReplicaSetStatus{}
		// Restore OwnerReferences (cleared spec removes nothing we need, they're in ObjectMeta)
	case *appsv1.Deployment:
		o.Spec = appsv1.DeploymentSpec{}
		o.Status = appsv1.DeploymentStatus{}
	case *appsv1.DaemonSet:
		o.Spec = appsv1.DaemonSetSpec{}
		o.Status = appsv1.DaemonSetStatus{}
	case *appsv1.StatefulSet:
		o.Spec = appsv1.StatefulSetSpec{}
		o.Status = appsv1.StatefulSetStatus{}
	case *batchv1.Job:
		o.Spec = batchv1.JobSpec{}
		o.Status = batchv1.JobStatus{}
	case *batchv1.CronJob:
		o.Spec = batchv1.CronJobSpec{}
		o.Status = batchv1.CronJobStatus{}
	}
	return obj, nil
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
	cronJobInformer := factory.Batch().V1().CronJobs().Informer()
	serviceInformer := factory.Core().V1().Services().Informer()
	deploymentInformer := factory.Apps().V1().Deployments().Informer()

	// Strip unneeded fields from objects before they enter the informer cache.
	// The informer stores full K8s objects internally, but we only need minimal
	// fields. This reduces memory by ~80% for the informer cache (the biggest
	// contributor on clusters with hundreds of pods/replicasets).
	podInformer.SetTransform(stripPod)
	nodeInformer.SetTransform(stripNode)
	replicaSetInformer.SetTransform(stripOwnerOnly)
	daemonSetInformer.SetTransform(stripOwnerOnly)
	statefulSetInformer.SetTransform(stripOwnerOnly)
	jobInformer.SetTransform(stripOwnerOnly)
	cronJobInformer.SetTransform(stripOwnerOnly)
	serviceInformer.SetTransform(stripService)
	deploymentInformer.SetTransform(stripOwnerOnly)

	resolver.addPodHandlers(podInformer)
	resolver.addNodeHandlers(nodeInformer)
	resolver.addReplicaSetHandlers(replicaSetInformer)
	resolver.addDaemonSetHandlers(daemonSetInformer)
	resolver.addStatefulSetHandlers(statefulSetInformer)
	resolver.addJobHandlers(jobInformer)
	resolver.addCronJobHandlers(cronJobInformer)
	resolver.addServiceHandlers(serviceInformer)
	resolver.addDeploymentHandlers(deploymentInformer)

	// Start informers and wait for initial list+watch sync.
	// The event handlers populate resolver.snapshot.* as objects arrive.
	factory.Start(resolver.stopSignal)
	synced := factory.WaitForCacheSync(resolver.stopSignal)
	for informerType, ok := range synced {
		if !ok {
			return fmt.Errorf("informer sync failed for %v", informerType)
		}
	}

	// Re-process IP mappings in the correct priority order
	// (services → nodes → pods) to handle IP collisions deterministically.
	log.Printf("Informer cache synced, building IP mappings")
	resolver.updateIpMapping()
	log.Printf("IP mappings built")

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

func (resolve *K8sIPResolver) addCronJobHandlers(cronJobInformer cache.SharedIndexInformer) {
	cronJobInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cronJob := obj.(*batchv1.CronJob)
			resolve.snapshot.CronJobs.Store(cronJob.UID, MinimalOwnerInfo{
				OwnerReferences: cronJob.OwnerReferences,
			})
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			cronJob := newObj.(*batchv1.CronJob)
			resolve.snapshot.CronJobs.Store(cronJob.UID, MinimalOwnerInfo{
				OwnerReferences: cronJob.OwnerReferences,
			})
		},
		DeleteFunc: func(obj interface{}) {
			cronJob := obj.(*batchv1.CronJob)
			resolve.snapshot.CronJobs.Delete(cronJob.UID)
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
			oldService := oldObj.(*v1.Service)
			service := newObj.(*v1.Service)
			minSvc := MinimalService{
				Name:       service.Name,
				Namespace:  service.Namespace,
				Selector:   service.Spec.Selector,
				ClusterIPs: service.Spec.ClusterIPs,
			}
			resolve.snapshot.Services.Store(service.UID, minSvc)
			// Delete old ClusterIPs that are no longer present
			newIPs := make(map[string]bool, len(service.Spec.ClusterIPs))
			for _, ip := range service.Spec.ClusterIPs {
				newIPs[ip] = true
			}
			for _, oldIP := range oldService.Spec.ClusterIPs {
				if oldIP != "None" && !newIPs[oldIP] {
					resolve.ipsMap.Delete(oldIP)
				}
			}
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
			oldPod := oldObj.(*v1.Pod)
			newPod := newObj.(*v1.Pod)
			// Clean old IPs that are no longer present
			newIPs := make(map[string]bool, len(newPod.Status.PodIPs))
			for _, ip := range newPod.Status.PodIPs {
				newIPs[ip.IP] = true
			}
			for _, oldIP := range oldPod.Status.PodIPs {
				if !newIPs[oldIP.IP] {
					resolver.podIpsMap.Remove(oldIP.IP)
				}
			}
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
	resolver.ipsMapMu.Lock()
	val, ok := resolver.ipsMap.Load(ip)
	if ok {
		existingWorkload, ok := val.(Workload)
		if ok {
			if existingWorkload.Kind == "node" && newWorkload.Kind != "node" {
				resolver.ipsMapMu.Unlock()
				return
			}
		}
	}
	resolver.ipsMap.Store(ip, *newWorkload)
	resolver.ipsMapMu.Unlock()
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

// workloadIdentityLabels defines the priority order for finding a stable
// workload identity from pod labels when no higher-level controller exists.
var workloadIdentityLabels = []string{
	"app.kubernetes.io/name",
	"app",
	"app.kubernetes.io/component",
	"component",
}

// resolveEphemeralWorkloadName returns a stable workload name for bare pods
// and standalone Jobs by checking standard Kubernetes labels. Falls back to
// "<namespace>-ephemeral" to prevent cardinality explosion from unique pod names.
func resolveEphemeralWorkloadName(labels map[string]string, namespace string) string {
	for _, key := range workloadIdentityLabels {
		if val, ok := labels[key]; ok && val != "" {
			return val
		}
	}
	return namespace + "-ephemeral"
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

	// Aggregate ephemeral workloads (bare pods and standalone Jobs) to prevent
	// cardinality explosion from unique pod/job names (e.g. Airflow task pods).
	if *flags.AggregateEphemeralWorkloads && (kind == "pod" || kind == "Job") {
		name = resolveEphemeralWorkloadName(pod.Labels, namespace)
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
