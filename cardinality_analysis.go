package main

import (
	"fmt"
	"runtime"
	"sort"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

// MetricCardinality tracks cardinality for each metric type
type MetricCardinality struct {
	Name       string
	SeriesCount int
	EstimatedMemoryMB int64
}

// AnalyzeCardinality examines which metrics are using the most memory
func AnalyzeCardinality(registry *prometheus.Registry) []MetricCardinality {
	var memStatsBefore runtime.MemStats
	runtime.ReadMemStats(&memStatsBefore)
	memBefore := memStatsBefore.Alloc
	
	start := time.Now()
	metricFamilies, err := registry.Gather()
	if err != nil {
		klog.Errorf("Failed to gather metrics for cardinality analysis: %v", err)
		return nil
	}
	gatherTime := time.Since(start)
	
	var memStatsAfter runtime.MemStats
	runtime.ReadMemStats(&memStatsAfter)
	memAfter := memStatsAfter.Alloc
	memDelta := memAfter - memBefore
	
	klog.Infof("CARDINALITY: Metric gather took %v, used %d MB memory", 
		gatherTime, memDelta/(1024*1024))
	
	// Count series per metric type
	metricCounts := make(map[string]int)
	totalSeries := 0
	
	for _, mf := range metricFamilies {
		seriesCount := len(mf.GetMetric())
		metricCounts[mf.GetName()] = seriesCount
		totalSeries += seriesCount
		
		// Log high cardinality metrics immediately
		if seriesCount > 100 {
			klog.Warningf("CARDINALITY: High cardinality metric: %s = %d series", 
				mf.GetName(), seriesCount)
		}
		
		// Log extremely high cardinality with sample labels
		if seriesCount > 1000 {
			klog.Errorf("CARDINALITY: CRITICAL cardinality metric: %s = %d series", 
				mf.GetName(), seriesCount)
			
			// Log first few label combinations to see pattern
			for i, metric := range mf.GetMetric() {
				if i >= 3 { // Only show first 3 examples
					break
				}
				labelStr := ""
				for _, label := range metric.GetLabel() {
					if labelStr != "" {
						labelStr += ","
					}
					labelStr += fmt.Sprintf("%s=%s", label.GetName(), label.GetValue())
				}
				klog.Errorf("CARDINALITY: Sample %d: {%s}", i+1, labelStr)
			}
		}
	}
	
	// Calculate estimated memory per series
	avgMemoryPerSeries := int64(0)
	if totalSeries > 0 {
		avgMemoryPerSeries = int64(memDelta) / int64(totalSeries)
	}
	
	// Sort by cardinality
	var results []MetricCardinality
	for name, count := range metricCounts {
		estimatedMB := (int64(count) * avgMemoryPerSeries) / (1024 * 1024)
		results = append(results, MetricCardinality{
			Name:              name,
			SeriesCount:       count,
			EstimatedMemoryMB: estimatedMB,
		})
	}
	
	sort.Slice(results, func(i, j int) bool {
		return results[i].SeriesCount > results[j].SeriesCount
	})
	
	// Log top 10 metrics by cardinality
	klog.Infof("CARDINALITY: Top 10 metrics by series count:")
	for i, metric := range results {
		if i >= 10 {
			break
		}
		klog.Infof("CARDINALITY: %d. %s: %d series (~%d MB)", 
			i+1, metric.Name, metric.SeriesCount, metric.EstimatedMemoryMB)
	}
	
	klog.Infof("CARDINALITY: Total metrics: %d, Total series: %d, Memory delta: %d MB", 
		len(results), totalSeries, memDelta/(1024*1024))
	
	return results
}

// LogCardinalityPeriodically runs cardinality analysis every 5 minutes
func LogCardinalityPeriodically(registry *prometheus.Registry) {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for {
			select {
			case <-ticker.C:
				var memStats runtime.MemStats
				runtime.ReadMemStats(&memStats)
				currentMemMB := memStats.Alloc / (1024 * 1024)
				
				if currentMemMB > 300 { // Only analyze when memory is high
					klog.Infof("CARDINALITY: Memory is %d MB, running analysis...", currentMemMB)
					AnalyzeCardinality(registry)
				}
			}
		}
	}()
}