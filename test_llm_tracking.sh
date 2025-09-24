#!/bin/bash

# Test script for LLM API tracking end-to-end flow
# Run this on a Linux system with eBPF support

set -e

echo "=== LLM API Tracking E2E Test ==="

# 1. Build the agent
echo "Building node-agent..."
go build -o node-agent .

# 2. Start the agent in background
echo "Starting node-agent..."
sudo ./node-agent --listen=:8080 &
AGENT_PID=$!

# Give agent time to start and load eBPF programs
sleep 5

# 3. Make test LLM API calls
echo "Making test LLM API calls..."

# OpenAI API call simulation
curl -X POST "https://api.openai.com/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer fake-key" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Hello"}],
    "max_tokens": 100
  }' || echo "Expected to fail - testing payload capture"

# Anthropic API call simulation  
curl -X POST "https://api.anthropic.com/v1/messages" \
  -H "Content-Type: application/json" \
  -H "x-api-key: fake-key" \
  -d '{
    "model": "claude-3-sonnet-20240229",
    "messages": [{"role": "user", "content": "Hello"}],
    "max_tokens": 100
  }' || echo "Expected to fail - testing payload capture"

# 4. Check metrics endpoint for captured data
echo "Checking metrics for LLM API calls..."
sleep 2
curl -s http://localhost:8080/metrics | grep -E "(http_requests|payload)" || echo "No HTTP metrics found yet"

# 5. Check traces endpoint if available
echo "Checking for trace data..."
curl -s http://localhost:8080/traces 2>/dev/null | head -20 || echo "No traces endpoint or data"

# 6. Check logs for payload capture
echo "Checking logs for payload data..."
pkill -f node-agent || true
wait $AGENT_PID 2>/dev/null || true

echo "=== Test Complete ==="
echo "Look for:"
echo "1. 'container_http_requests_total' metrics with LLM API destinations"
echo "2. Payload data in trace logs (base64 encoded JSON)"
echo "3. No more 'Payload too small' errors"