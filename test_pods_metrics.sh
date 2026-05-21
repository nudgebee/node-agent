#!/bin/bash

# Script to test metrics endpoint for each nudgebee-agent pod
# Usage: ./test_pods_metrics.sh

set -e

NAMESPACE="${NAMESPACE:-nudgebee}"
APP_LABEL="${APP_LABEL:-app=nudgebee-node-agent}"
BASE_PORT="${BASE_PORT:-8090}"

echo "=== Testing Metrics Endpoint for All Nudgebee Agent Pods ==="
echo "Namespace: $NAMESPACE"
echo "App Label: $APP_LABEL"
echo ""

# Get all pod names
PODS=($(kubectl get pods -n $NAMESPACE -l $APP_LABEL -o jsonpath='{.items[*].metadata.name}'))

if [ ${#PODS[@]} -eq 0 ]; then
    echo "❌ No pods found with label $APP_LABEL in namespace $NAMESPACE"
    exit 1
fi

echo "Found ${#PODS[@]} pods to test:"
for pod in "${PODS[@]}"; do
    echo "  - $pod"
done
echo ""

# Function to test a single pod
test_pod() {
    local pod_name=$1
    local port=$2
    
    echo "🧪 Testing pod: $pod_name"
    echo "   Port-forward: localhost:$port -> $pod_name:80"
    
    # Start port-forward in background
    kubectl port-forward -n $NAMESPACE pod/$pod_name $port:80 > /tmp/pf_$pod_name.log 2>&1 &
    local pf_pid=$!
    
    # Wait for port-forward to be ready
    sleep 2
    
    # Test the connection
    local success=false
    local http_code=$(curl -s --max-time 10 -w "%{http_code}" localhost:$port/metrics -o /tmp/metrics_$pod_name.txt 2>/dev/null)
    if [ "$http_code" = "200" ]; then
        local metric_count=$(wc -l < /tmp/metrics_$pod_name.txt)
        local response_time=$(curl -s -w "%{time_total}" --max-time 10 localhost:$port/metrics -o /dev/null 2>/dev/null || echo "TIMEOUT")
        
        echo "   ✅ SUCCESS: $metric_count metrics, ${response_time}s response time"
        success=true
    else
        echo "   ❌ FAILED: HTTP $http_code (or connection refused/timeout)"
    fi
    
    # Clean up port-forward
    kill $pf_pid 2>/dev/null || true
    wait $pf_pid 2>/dev/null || true
    
    # Show sample metrics if successful
    if $success; then
        echo "   📊 Sample metrics:"
        head -3 /tmp/metrics_$pod_name.txt | sed 's/^/      /'
        echo ""
    else
        echo "   🔍 Port-forward log:"
        tail -3 /tmp/pf_$pod_name.log | sed 's/^/      /'
        echo ""
    fi
    
    return $([ "$success" = true ] && echo 0 || echo 1)
}

# Test each pod
successful_pods=0
failed_pods=0

for i in "${!PODS[@]}"; do
    pod_name=${PODS[$i]}
    port=$((BASE_PORT + i))
    
    if test_pod "$pod_name" "$port"; then
        ((successful_pods++))
    else
        ((failed_pods++))
    fi
    
    # Small delay between tests
    sleep 1
done

# Summary
echo "=========================================="
echo "📋 SUMMARY:"
echo "   ✅ Successful pods: $successful_pods"
echo "   ❌ Failed pods: $failed_pods"
echo "   📊 Total pods tested: ${#PODS[@]}"

if [ $failed_pods -eq 0 ]; then
    echo "   🎉 All pods are responding correctly!"
else
    echo "   ⚠️  Some pods are not responding to metrics requests"
fi

# Cleanup temp files
rm -f /tmp/pf_*.log /tmp/metrics_*.txt

exit $failed_pods