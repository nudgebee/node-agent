package common

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	lrucache "github.com/hashicorp/golang-lru/v2"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/api/batch/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const MAX_RESOLVED_DNS = 10000 // arbitrary limit
const MAX_PODS_LIMIT = 30000   // arbitrary limit

type clusterSnapshot struct {
	Pods           sync.Map // map[types.UID]v1.Pod
	Nodes          sync.Map // map[types.UID]v1.Node
	ReplicaSets    sync.Map // map[types.UID]appsv1.ReplicaSet
	DaemonSets     sync.Map // map[types.UID]appsv1.DaemonSet
	StatefulSets   sync.Map // map[types.UID]appsv1.StatefulSet
	Jobs           sync.Map // map[types.UID]batchv1.Job
	Services       sync.Map // map[types.UID]v1.Service
	Deployments    sync.Map // map[types.UID]appsv1.Deployment
	CronJobs       sync.Map // map[types.UID]batchv1.CronJob or batchv1beta.CronJob
	PodDescriptors sync.Map // map[types.UID]Workload
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
	if resolveDns {
		var err error
		dnsCache, err = lrucache.New[string, string](MAX_RESOLVED_DNS)
		if err != nil {
			return nil, err
		}
	} else {
		dnsCache = nil
	}
	var podCache *lrucache.Cache[string, Workload]
	podCache, err := lrucache.New[string, Workload](MAX_PODS_LIMIT)
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
		} else {
			hosts, err := net.LookupAddr(ip)
			if err == nil && len(hosts) > 0 {
				host = hosts[0]
			}
			resolver.dnsResolvedIps.Add(ip, host)
		}
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
		} else {
			hosts, err := net.LookupAddr(ip)
			if err == nil && len(hosts) > 0 {
				host = hosts[0]
			}
			resolver.dnsResolvedIps.Add(ip, host)
		}
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
			replicaSet := obj.(*appsv1.ReplicaSet)
			resolve.snapshot.ReplicaSets.Store(replicaSet.UID, *replicaSet)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			replicaSet := newObj.(*appsv1.ReplicaSet)
			resolve.snapshot.ReplicaSets.Store(replicaSet.UID, *replicaSet)
		},
		DeleteFunc: func(obj interface{}) {
			replicaSet := obj.(*appsv1.ReplicaSet)
			resolve.snapshot.ReplicaSets.Delete(replicaSet.UID)
		},
	})
}

func (resolve *K8sIPResolver) addDaemonSetHandlers(daemonSetInformer cache.SharedIndexInformer) {
	daemonSetInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			daemonSet := obj.(*appsv1.DaemonSet)
			resolve.snapshot.DaemonSets.Store(daemonSet.UID, *daemonSet)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			daemonSet := newObj.(*appsv1.DaemonSet)
			resolve.snapshot.DaemonSets.Store(daemonSet.UID, *daemonSet)
		},
		DeleteFunc: func(obj interface{}) {
			daemonSet := obj.(*appsv1.DaemonSet)
			resolve.snapshot.DaemonSets.Delete(daemonSet.UID)
		},
	})
}

func (resolve *K8sIPResolver) addStatefulSetHandlers(statefulSetInformer cache.SharedIndexInformer) {
	statefulSetInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			statefulSet := obj.(*appsv1.StatefulSet)
			resolve.snapshot.StatefulSets.Store(statefulSet.UID, *statefulSet)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			statefulSet := newObj.(*appsv1.StatefulSet)
			resolve.snapshot.StatefulSets.Store(statefulSet.UID, *statefulSet)
		},
		DeleteFunc: func(obj interface{}) {
			statefulSet := obj.(*appsv1.StatefulSet)
			resolve.snapshot.StatefulSets.Delete(statefulSet.UID)
		},
	})
}

func (resolve *K8sIPResolver) addJobHandlers(jobInformer cache.SharedIndexInformer) {
	jobInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			job := obj.(*batchv1.Job)
			resolve.snapshot.Jobs.Store(job.UID, *job)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			job := newObj.(*batchv1.Job)
			resolve.snapshot.Jobs.Store(job.UID, *job)
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
			resolve.snapshot.Services.Store(service.UID, *service)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			service := newObj.(*v1.Service)
			resolve.snapshot.Services.Store(service.UID, *service)
		},
		DeleteFunc: func(obj interface{}) {
			service := obj.(*v1.Service)
			resolve.snapshot.Services.Delete(service.UID)
		},
	})
}

func (resolve *K8sIPResolver) addDeploymentHandlers(deploymentInformer cache.SharedIndexInformer) {
	deploymentInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			deployment := obj.(*appsv1.Deployment)
			resolve.snapshot.Deployments.Store(deployment.UID, *deployment)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			deployment := newObj.(*appsv1.Deployment)
			resolve.snapshot.Deployments.Store(deployment.UID, *deployment)
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
			for _, podIp := range pod.Status.PodIPs {
				resolver.podIpsMap.Remove(podIp.IP)
			}
		},
	})
}

func (resolver *K8sIPResolver) handlePodAdd(pod *v1.Pod) bool {
	resolver.snapshot.Pods.Store(pod.UID, *pod)
	entry := resolver.resolvePodDescriptor(pod)
	instanceMeta, ok := resolver.instanceMetaMap.Load(pod.Spec.NodeName)
	region := ""
	zone := ""
	if ok {
		instanceMeta, ok := instanceMeta.(InstanceMeta)
		if ok {
			region = instanceMeta.Region
			zone = instanceMeta.Zone
		} else {
			log.Printf("Type confusion in instance meta for node %s", pod.Spec.NodeName)
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
	resolver.snapshot.Nodes.Store(node.UID, *node)
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
		resolver.snapshot.Pods.Store(pod.UID, pod)
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
		resolver.snapshot.Nodes.Store(node.UID, node)
	}

	replicasets, err := resolver.clientset.AppsV1().ReplicaSets("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return errors.New("error getting replicasets, aborting snapshot update")
	}
	for _, rs := range replicasets.Items {
		resolver.snapshot.ReplicaSets.Store(rs.ObjectMeta.UID, rs)
	}

	daemonsets, err := resolver.clientset.AppsV1().DaemonSets("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return errors.New("error getting daemonsets, aborting snapshot update")
	}
	for _, ds := range daemonsets.Items {
		resolver.snapshot.DaemonSets.Store(ds.ObjectMeta.UID, ds)
	}

	statefulsets, err := resolver.clientset.AppsV1().StatefulSets("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return errors.New("error getting statefulsets, aborting snapshot update")
	}
	for _, ss := range statefulsets.Items {
		resolver.snapshot.StatefulSets.Store(ss.ObjectMeta.UID, ss)
	}

	jobs, err := resolver.clientset.BatchV1().Jobs("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return errors.New("error getting jobs, aborting snapshot update")
	}
	for _, job := range jobs.Items {
		resolver.snapshot.Jobs.Store(job.ObjectMeta.UID, job)
	}

	services, err := resolver.clientset.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return errors.New("error getting services, aborting snapshot update")
	}
	for _, service := range services.Items {
		resolver.snapshot.Services.Store(service.UID, service)
	}

	deployments, err := resolver.clientset.AppsV1().Deployments("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return errors.New("error getting deployments, aborting snapshot update")
	}
	for _, deployment := range deployments.Items {
		resolver.snapshot.Deployments.Store(deployment.UID, deployment)
	}

	cronJobs, err := resolver.clientset.BatchV1().CronJobs("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		cronJobs, err := resolver.clientset.BatchV1beta1().CronJobs("").List(context.Background(), metav1.ListOptions{})
		if err != nil {
			return errors.New("error getting cronjobs, aborting snapshot update")
		}
		for _, cronJob := range cronJobs.Items {
			resolver.snapshot.CronJobs.Store(cronJob.UID, cronJob)
		}
	}
	for _, cronJob := range cronJobs.Items {
		resolver.snapshot.CronJobs.Store(cronJob.UID, cronJob)
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
		service, ok := val.(v1.Service)
		if !ok {
			log.Printf("Type confusion in services map")
			return true // continue
		}
		// services has (potentially multiple) ClusterIP
		workload := Workload{
			Name:      service.Name,
			Namespace: service.Namespace,
			Kind:      "Service",
			Zone:      "",
			Region:    "",
			Instance:  "",
		}

		// TODO maybe try to match service to workload
		for _, clusterIp := range service.Spec.ClusterIPs {
			if clusterIp != "None" {
				resolver.storeWorkloadsIP(clusterIp, &workload)
			}
		}
		return true
	})

	resolver.snapshot.Nodes.Range(func(key any, value any) bool {
		node, ok := value.(v1.Node)
		if !ok {
			log.Printf("Type confusion in nodes map")
			return true // continue
		}
		for _, nodeAddress := range node.Status.Addresses {
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
		pod, ok := value.(v1.Pod)
		if !ok {
			log.Printf("Type confusion in pods map")
			return true // continue
		}
		entry := resolver.resolvePodDescriptor(&pod)
		for _, podIp := range pod.Status.PodIPs {
			// if ip is already in the map, override only if current pod is running
			resolver.storeWorkloadsIP(podIp.IP, &entry)
			instanceMeta, ok := resolver.instanceMetaMap.Load(pod.Spec.NodeName)
			region := ""
			zone := ""
			if ok {
				instanceMeta, ok := instanceMeta.(InstanceMeta)
				if ok {
					region = instanceMeta.Region
					zone = instanceMeta.Zone
				} else {
					log.Printf("Type confusion in instance meta for node %s", pod.Spec.NodeName)
				}
			} else {
				log.Printf("Missing instance meta for node %s", pod.Spec.NodeName)
			}
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

// an ugly function to go up one level in hierarchy. maybe there's a better way to do it
// the snapshot is maintained to avoid using an API request for each resolving
func (resolver *K8sIPResolver) getControllerOfOwner(originalOwner *metav1.OwnerReference) (*metav1.OwnerReference, error) {
	switch originalOwner.Kind {
	case "ReplicaSet":
		replicaSetVal, ok := resolver.snapshot.ReplicaSets.Load(originalOwner.UID)
		if !ok {
			return nil, errors.New("Missing replicaset for UID " + string(originalOwner.UID))
		}
		replicaSet, ok := replicaSetVal.(appsv1.ReplicaSet)
		if !ok {
			return nil, errors.New("type confusion in replicasets map")
		}
		owner := metav1.GetControllerOf(&replicaSet)
		return owner, nil
	case "DaemonSet":
		daemonSetVal, ok := resolver.snapshot.DaemonSets.Load(originalOwner.UID)
		if !ok {
			return nil, errors.New("Missing daemonset for UID " + string(originalOwner.UID))
		}
		daemonSet, ok := daemonSetVal.(appsv1.DaemonSet)
		if !ok {
			return nil, errors.New("type confusion in daemonsets map")
		}
		return metav1.GetControllerOf(&daemonSet), nil
	case "StatefulSet":
		statefulSetVal, ok := resolver.snapshot.StatefulSets.Load(originalOwner.UID)
		if !ok {
			return nil, errors.New("Missing statefulset for UID " + string(originalOwner.UID))
		}
		statefulSet, ok := statefulSetVal.(appsv1.StatefulSet)
		if !ok {
			return nil, errors.New("type confusion in statefulsets map")
		}
		return metav1.GetControllerOf(&statefulSet), nil
	case "Job":
		jobVal, ok := resolver.snapshot.Jobs.Load(originalOwner.UID)
		if !ok {
			return nil, errors.New("Missing job for UID " + string(originalOwner.UID))
		}
		job, ok := jobVal.(batchv1.Job)
		if !ok {
			return nil, errors.New("type confusion in jobs map")
		}
		return metav1.GetControllerOf(&job), nil
	case "Deployment":
		deploymentVal, ok := resolver.snapshot.Deployments.Load(originalOwner.UID)
		if !ok {
			return nil, errors.New("Missing deployment for UID " + string(originalOwner.UID))
		}
		deployment, ok := deploymentVal.(appsv1.Deployment)
		if !ok {
			return nil, errors.New("type confusion in deployments map")
		}
		return metav1.GetControllerOf(&deployment), nil
	case "CronJob":
		cronJobVal, ok := resolver.snapshot.CronJobs.Load(originalOwner.UID)
		if !ok {
			return nil, errors.New("Missing cronjob for UID " + string(originalOwner.UID))
		}
		cronJob, ok := cronJobVal.(batchv1.CronJob)
		if !ok {
			cronJob, ok := cronJobVal.(v1beta1.CronJob)
			if !ok {
				return nil, errors.New("type confusion in cronjobs map")
			}
			return metav1.GetControllerOf(&cronJob), nil
		}

		return metav1.GetControllerOf(&cronJob), nil
	}
	return nil, errors.New("Unsupported kind for lookup - " + originalOwner.Kind)
}

func (resolver *K8sIPResolver) resolvePodDescriptor(pod *v1.Pod) Workload {
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
	owner := metav1.GetControllerOf(pod)
	// climbing up the owners' hierarchy. if an error occurs, we take the data we got and save
	// the error to know we shouldn't save this resolution to the descriptors map and retry later.
	for owner != nil {
		name = owner.Name
		kind = owner.Kind
		owner, err = resolver.getControllerOfOwner(owner)
		if err != nil {
			log.Printf("Warning: couldn't retrieve owner of %v - %v. This might happen when starting up", name, err)
		}
	}
	instanceMeta, ok := resolver.instanceMetaMap.Load(pod.Spec.NodeName)
	region := ""
	zone := ""
	if ok {
		instanceMeta, ok := instanceMeta.(InstanceMeta)
		if ok {
			region = instanceMeta.Region
			zone = instanceMeta.Zone
		} else {
			log.Printf("Type confusion in instance meta for node %s", pod.Spec.NodeName)
		}
	} else {
		log.Printf("Missing instance meta for node %s", pod.Spec.NodeName)
		resolver.instanceMetaMap.Range(func(key, value interface{}) bool {
			log.Printf("key: %s, value: %v", key, value)
			return true
		})
	}
	result := Workload{
		Name:      name,
		Namespace: namespace,
		Kind:      kind,
		Region:    region,
		Zone:      zone,
		Instance:  pod.Spec.NodeName,
	}
	if err == nil {
		resolver.snapshot.PodDescriptors.Store(pod.UID, result)
	}
	return result
}

func (resolver *K8sIPResolver) ResolvePodOwner(podName string, podNamespace string) Workload {
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
	return resolver.resolvePodDescriptor(pods)
}
