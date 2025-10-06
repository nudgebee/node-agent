package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"k8s.io/klog/v2"
)

type MetricInfo struct {
	Name   string `json:"name"`
	Count  int    `json:"count"`
	Memory int64  `json:"memory_mb"`
}

type DebugInfo struct {
	TotalMetrics  int          `json:"total_metrics"`
	TotalMemoryMB int64        `json:"total_memory_mb"`
	TopMetrics    []MetricInfo `json:"top_metrics"`
	Timestamp     time.Time    `json:"timestamp"`
}

func debugMetricsHandler(registry *prometheus.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		
		// Get current memory before gathering
		memBefore := memStats.Alloc
		
		klog.Infof("DEBUG: Starting metric analysis - Memory before: %d MB", memBefore/(1024*1024))
		
		// Gather metrics with timeout
		start := time.Now()
		metricFamilies, err := registry.Gather()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to gather metrics: %v", err), 500)
			return
		}
		
		runtime.ReadMemStats(&memStats)
		memAfter := memStats.Alloc
		gatherTime := time.Since(start)
		
		klog.Infof("DEBUG: Metric gather completed - Memory after: %d MB, Delta: %d MB, Time: %v", 
			memAfter/(1024*1024), (memAfter-memBefore)/(1024*1024), gatherTime)
		
		// Analyze metric cardinality
		metricCounts := make(map[string]int)
		totalSeries := 0
		
		for _, mf := range metricFamilies {
			seriesCount := 0
			for _, m := range mf.GetMetric() {
				seriesCount++
				totalSeries++
				
				// Log high cardinality metrics
				if seriesCount%1000 == 0 {
					labelStr := formatLabels(m.GetLabel())
					klog.Infof("DEBUG: High cardinality metric %s series %d: %s", 
						mf.GetName(), seriesCount, labelStr)
				}
			}
			metricCounts[mf.GetName()] = seriesCount
			
			if seriesCount > 100 {
				klog.Warningf("DEBUG: High cardinality metric found: %s with %d series", 
					mf.GetName(), seriesCount)
			}
		}
		
		// Sort metrics by cardinality
		type metricPair struct {
			name  string
			count int
		}
		
		var sorted []metricPair
		for name, count := range metricCounts {
			sorted = append(sorted, metricPair{name, count})
		}
		
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].count > sorted[j].count
		})
		
		// Estimate memory per metric (rough calculation)
		avgMemoryPerSeries := int64(0)
		if totalSeries > 0 {
			avgMemoryPerSeries = int64(memAfter - memBefore) / int64(totalSeries)
		}
		
		// Build response
		var topMetrics []MetricInfo
		for i, pair := range sorted {
			if i >= 10 { // Top 10
				break
			}
			topMetrics = append(topMetrics, MetricInfo{
				Name:   pair.name,
				Count:  pair.count,
				Memory: int64(pair.count) * avgMemoryPerSeries / (1024 * 1024),
			})
		}
		
		debug := DebugInfo{
			TotalMetrics:  totalSeries,
			TotalMemoryMB: int64(memAfter - memBefore) / (1024 * 1024),
			TopMetrics:    topMetrics,
			Timestamp:     time.Now(),
		}
		
		klog.Infof("DEBUG: Analysis complete - Total series: %d, Top metric: %s (%d series)", 
			totalSeries, sorted[0].name, sorted[0].count)
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(debug)
	}
}

func formatLabels(labels []*dto.LabelPair) string {
	var parts []string
	for _, label := range labels {
		parts = append(parts, fmt.Sprintf("%s=%s", label.GetName(), label.GetValue()))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// Add memory monitoring middleware
func memoryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		
		if memStats.Alloc > 800*1024*1024 { // 800MB threshold
			klog.Errorf("MEMORY: Critical memory usage: %d MB - rejecting request to %s", 
				memStats.Alloc/(1024*1024), r.URL.Path)
			http.Error(w, "Service temporarily unavailable - high memory usage", 503)
			return
		}
		
		if memStats.Alloc > 600*1024*1024 { // 600MB warning
			klog.Warningf("MEMORY: High memory usage: %d MB - serving request to %s", 
				memStats.Alloc/(1024*1024), r.URL.Path)
		}
		
		start := time.Now()
		memBefore := memStats.Alloc
		
		next.ServeHTTP(w, r)
		
		runtime.ReadMemStats(&memStats)
		duration := time.Since(start)
		memDelta := int64(memStats.Alloc) - int64(memBefore)
		
		if duration > 5*time.Second || memDelta > 100*1024*1024 {
			klog.Warningf("SLOW/MEMORY: Request %s took %v, memory delta: %d MB", 
				r.URL.Path, duration, memDelta/(1024*1024))
		}
	})
}