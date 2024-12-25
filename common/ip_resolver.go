package common

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	lrucache "github.com/hashicorp/golang-lru/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const MAX_RESOLVED_DNS = 10000
const MAX_PODS = 20000

var reregisterWatchSleepDuration = 1 * time.Second

var (
	watchEventsCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nudgbee_watcher_events_count",
	}, []string{"object_type"})
	watchResetsCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nudgebee_watcher_resets_count",
	}, []string{"object_type"})
)

type clusterSnapshot struct {
	Pods           sync.Map // map[types.UID]v1.Pod
	Nodes          sync.Map // map[types.UID]v1.Node
	PodDescriptors sync.Map // map[types.UID]Workload
}

type K8sIPResolver struct {
	clientset        kubernetes.Interface
	snapshot         clusterSnapshot
	ipsMap           sync.Map
	stopSignal       chan bool
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
	podsCache, err := lrucache.New[string, Workload](MAX_RESOLVED_DNS)
	if err != nil {
		return nil, err
	}

	return &K8sIPResolver{
		clientset:        clientset,
		snapshot:         clusterSnapshot{},
		ipsMap:           sync.Map{},
		stopSignal:       make(chan bool),
		shouldResolveDns: resolveDns,
		dnsResolvedIps:   dnsCache,
		podIpsMap:        podsCache,
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

func (resolver *K8sIPResolver) StartWatching() error {
	// register watchers
	podsWatcher, err := resolver.clientset.CoreV1().Pods("").Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching pods changes - %v", err)
	}

	nodesWatcher, err := resolver.clientset.CoreV1().Nodes().Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching nodes changes - %v", err)
	}

	replicasetsWatcher, err := resolver.clientset.AppsV1().ReplicaSets("").Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching replicasets changes - %v", err)
	}

	daemonsetsWatcher, err := resolver.clientset.AppsV1().DaemonSets("").Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching daemonsets changes - %v", err)
	}

	statefulsetsWatcher, err := resolver.clientset.AppsV1().StatefulSets("").Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching statefulsets changes - %v", err)
	}

	jobsWatcher, err := resolver.clientset.BatchV1().Jobs("").Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching jobs changes - %v", err)
	}

	servicesWatcher, err := resolver.clientset.CoreV1().Services("").Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching services changes - %v", err)
	}

	deploymentsWatcher, err := resolver.clientset.AppsV1().Deployments("").Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error watching deployments changes - %v", err)
	}

	cronJobsWatcher, err := resolver.startCronjobWatcher()
	if err != nil {
		klog.Errorf("failed to init watcher %v", err)
		return fmt.Errorf("error watching cronjobs changes - %v", err)
	}
	log.Printf("registered IP watcher")
	// invoke a watching function
	go func() {
		for {
			select {
			case <-resolver.stopSignal:
				podsWatcher.Stop()
				nodesWatcher.Stop()
				replicasetsWatcher.Stop()
				daemonsetsWatcher.Stop()
				statefulsetsWatcher.Stop()
				jobsWatcher.Stop()
				servicesWatcher.Stop()
				deploymentsWatcher.Stop()
				cronJobsWatcher.Stop()
				return
			case podEvent, ok := <-podsWatcher.ResultChan():
				{

					if !ok {
						watchResetsCounter.WithLabelValues("pod").Inc()
						podsWatcher, err = resolver.clientset.CoreV1().Pods("").Watch(context.Background(), metav1.ListOptions{})
						if err != nil {
							time.Sleep(reregisterWatchSleepDuration)
						}
						continue
					}
					watchEventsCounter.WithLabelValues("pod").Inc()
					resolver.handlePodWatchEvent(&podEvent)
				}
			case nodeEvent, ok := <-nodesWatcher.ResultChan():
				{
					if !ok {
						watchResetsCounter.WithLabelValues("node").Inc()
						nodesWatcher, err = resolver.clientset.CoreV1().Nodes().Watch(context.Background(), metav1.ListOptions{})
						if err != nil {
							time.Sleep(reregisterWatchSleepDuration)
						}
						continue
					}
					watchEventsCounter.WithLabelValues("node").Inc()
					resolver.handleNodeWatchEvent(&nodeEvent)
				}
			}
		}
	}()

	// get initial state
	err = resolver.getResolvedClusterSnapshot()
	if err != nil {
		resolver.StopWatching()
		return fmt.Errorf("error retrieving cluster's initial state: %v", err)
	}

	return nil
}

func (resolver *K8sIPResolver) StartWatchingV2(ip string, entry *Workload) {

	factory := informers.NewSharedInformerFactory(resolver.clientset, time.Minute*10)
	// Define individual informers
	podInformer := factory.Core().V1().Pods().Informer()
	nodeInformer := factory.Core().V1().Nodes().Informer()

	resolver.addPodHandlers(podInformer)
	resolver.addNodeHandlers(nodeInformer)
}
func (resolver *K8sIPResolver) addPodHandlers(podInformer cache.SharedIndexInformer) {
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)
			log.Printf("Pod added: %s/%s", pod.Namespace, pod.Name)
			resolver.handlePodAdd(pod)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newPod := newObj.(*v1.Pod)
			log.Printf("Pod updated: %s/%s", newPod.Namespace, newPod.Name)
			resolver.handlePodAdd(newPod)
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)
			log.Printf("Pod deleted: %s/%s", pod.Namespace, pod.Name)
			resolver.snapshot.Pods.Delete(pod.UID)
			resolver.snapshot.PodDescriptors.Delete(pod.UID)
			for _, podIp := range pod.Status.PodIPs {
				resolver.podIpsMap.Remove(podIp.IP)
			}
		},
	})
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

func (resolver *K8sIPResolver) startCronjobWatcher() (watch.Interface, error) {
	cronJobsWatcher, err := resolver.clientset.BatchV1().CronJobs("").Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		return resolver.clientset.BatchV1beta1().CronJobs("").Watch(context.Background(), metav1.ListOptions{})
	}

	return cronJobsWatcher, nil
}

func (resolver *K8sIPResolver) StopWatching() {
	resolver.stopSignal <- true
}

func (resolver *K8sIPResolver) handlePodWatchEvent(podEvent *watch.Event) {
	switch podEvent.Type {
	case watch.Added, watch.Modified:
		pod, ok := podEvent.Object.(*v1.Pod)
		if !ok {
			return
		}
		resolver.handlePodAdd(pod)
	case watch.Deleted:
		if val, ok := podEvent.Object.(*v1.Pod); ok {
			resolver.snapshot.Pods.Delete(val.UID)
			resolver.snapshot.PodDescriptors.Delete(val.UID)
		}
	}
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

func (resolver *K8sIPResolver) handleNodeWatchEvent(nodeEvent *watch.Event) {
	switch nodeEvent.Type {
	case watch.Added, watch.Modified:
		// extract region and zone from attributes
		node, ok := nodeEvent.Object.(*v1.Node)
		if !ok {
			return
		}
		shouldReturn := resolver.handleNodeEvent(node)
		if shouldReturn {
			return
		}
	case watch.Deleted:
		if val, ok := nodeEvent.Object.(*v1.Node); ok {
			resolver.snapshot.Nodes.Delete(val.UID)
			resolver.instanceMetaMap.Delete(val.Name)
		}
	}
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
	return nil
}

// add mapping from ip to resolved host to an existing map,
// based on the given cluster snapshot
func (resolver *K8sIPResolver) updateIpMapping() {
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
