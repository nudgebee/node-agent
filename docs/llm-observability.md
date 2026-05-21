# LLM observability

The agent identifies outbound traffic to large-language-model APIs and
exposes per-request metrics — model name, token counts, latency,
time-to-first-token, error class, and estimated cost — alongside the
container, pod, and namespace the request came from. No code changes,
SDK wrappers, or proxies are required: detection happens in eBPF on
the node.

This feature is specific to the nudgebee fork and is not present in
upstream `coroot/coroot-node-agent`.

## Supported providers

| Provider                | Match                                                                   |
| ----------------------- | ----------------------------------------------------------------------- |
| OpenAI                  | `api.openai.com` (and subdomains)                                       |
| Anthropic               | `api.anthropic.com`, `claude.ai`                                        |
| Google Gemini / Vertex  | `generativelanguage.googleapis.com`, `ai.googleapis.com`, `aiplatform.googleapis.com`, regional Vertex endpoints |
| AWS Bedrock             | `bedrock-runtime.<region>.amazonaws.com`                                |
| Azure OpenAI            | `<resource>.openai.azure.com`                                           |
| Cohere                  | `api.cohere.com`, `api.cohere.ai`                                       |
| OpenAI-compatible       | `api.groq.com`, `api.together.xyz`, `api.fireworks.ai`, `api.deepseek.com`, `api.mistral.ai`, `api.perplexity.ai` |

When the hostname doesn't match, the path is checked for known LLM
patterns (`/v1/messages`, `:generateContent`, `/models/gemini`, the
Bedrock `/model/.../converse` form, etc.) as a fallback.

## How detection works

Three signals are used, in priority order:

1. **DNS cache** — when an in-cluster DNS reply resolves an LLM
   hostname, every IP in the reply is cached. Subsequent TCP
   connections to those IPs are tagged at `connect()` time.
2. **TLS SNI** — the ClientHello is parsed by an eBPF probe. The SNI
   hostname matches the provider tables directly. SNI-based tagging
   is the primary mechanism for everything except Google APIs (Google
   shares anycast IPs across Gemini / Compute / etc., so SNI is the
   only reliable disambiguator).
3. **Late tag from HTTP headers** — when an HTTP/1.1 `Host` or HTTP/2
   `:authority` is observed mid-request, a connection that wasn't
   already tagged by DNS or SNI gets retroactively classified.

For Google APIs specifically, IP caching is suppressed because the
anycast pool overlaps with non-LLM services. Detection there is
SNI + header-driven only.

## What gets extracted

Per request the agent records:

- Model name (read from response body's `"model"` field, with
  fallbacks to request body and URL path patterns)
- Input / output / cached-input token counts
- Tool / function-call invocation count
- Total request duration
- Time-to-first-token (streaming requests only)
- HTTP response status code
- Streaming flag
- Container ID, pod name, namespace
- W3C trace context (`traceparent`) if present

Streaming responses (SSE / HTTP/2 DATA frames) are accumulated into a
bounded ring buffer (64 KB tail, since `usage` and `finish_reason`
typically live near the end). Completion markers (`data: [DONE]` for
OpenAI, `message_stop` for Anthropic, `finishReason` for Gemini) are
detected inline. Idle streams time out after 30 s; the hard upper
bound on a single stream is 5 minutes.

## Metrics emitted

All LLM metrics live under the `container_llm_` prefix. Standard
container labels (`container_id`, `namespace`, `pod`) are present
on every series; LLM-specific labels are listed per metric below.

| Metric                                          | Type      | LLM-specific labels                                                                                                          |
| ----------------------------------------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `container_llm_requests_total`                  | counter   | `gen_ai_operation_name`, `gen_ai_request_model`, `gen_ai_provider_name`, `server_address`, `http_response_status_code` |
| `container_llm_token_usage_total`               | counter   | + `gen_ai_token_type` (`input`, `output`)                                                                                    |
| `container_llm_cached_input_tokens_total`       | counter   | same as token_usage                                                                                                          |
| `container_llm_tool_calls_total`                | counter   | same as requests                                                                                                             |
| `container_llm_errors_total`                    | counter   | + `error_type` (`rate_limit`, `timeout`, `invalid_request`, `server_error`, `auth_error`)                                    |
| `container_llm_request_duration_seconds`        | histogram | OTel GenAI buckets (0.01 – 81.92 s)                                                                                          |
| `container_llm_time_to_first_token_seconds`     | histogram | OTel GenAI buckets (0.001 – 10 s); streaming only                                                                            |
| `container_llm_tokens_per_second`               | histogram | streaming only                                                                                                               |
| `container_llm_cost_usd_total`                  | counter   | provider+model labels                                                                                                        |
| `node_agent_llm_sni_tags_total`                 | counter   | `provider` — diagnostic for SNI tagging coverage                                                                             |
| `node_agent_hpack_decode_errors_total`          | counter   | mid-stream-join indicator (see *Limitations*)                                                                                |

Label naming follows the OpenTelemetry GenAI semantic conventions
where applicable.

## Cost estimation

A static pricing table (`containers/llm_pricing.go`) maps
`<provider>:<model-prefix>` to per-million-token rates (input,
output, and cached-input where applicable). Longest-prefix wins, so
`gpt-4o-2024-05-13` resolves to the `gpt-4o` row.

Cost is computed as:

```
cost = (input - cached) * inputRate/1M
     + output           * outputRate/1M
     + cached           * cachedRate/1M
```

Coverage includes OpenAI (GPT-4, GPT-4o, o1, o3, embeddings),
Anthropic Claude 3 / 3.5, Google Gemini 1.5 / 2.x / 3.x, AWS Bedrock
(Anthropic, Nova, Llama, Mistral, Cohere), and direct Cohere.
OpenAI-compatible providers have placeholder entries and may report
zero cost depending on the model string.

Numbers are **list prices** — no volume or contract discounts are
applied. If no row matches, cost is 0 and the request is still
counted in the other metrics.

## Sample queries

Cost-by-model in the last hour:

```promql
sum by (gen_ai_request_model) (
  rate(container_llm_cost_usd_total[1h])
) * 3600
```

P95 time-to-first-token, per provider, last 5 m (streaming endpoints):

```promql
histogram_quantile(
  0.95,
  sum by (gen_ai_provider_name, le) (
    rate(container_llm_time_to_first_token_seconds_bucket[5m])
  )
)
```

Rate-limit error count per pod:

```promql
sum by (namespace, pod) (
  rate(container_llm_errors_total{error_type="rate_limit"}[5m])
)
```

## Limitations

- **HTTP/2 mid-stream-join.** If a workload's HTTP/2 connection to a
  provider predates the agent attaching to that workload's TLS session,
  HPACK dynamic-table state is unrecoverable and the agent will see
  malformed frames for the lifetime of that connection. Mitigations:
  restart the workload after rolling out the agent (forces fresh
  connections), or rely on SNI-based tagging which works regardless of
  HPACK state. `node_agent_hpack_decode_errors_total` is the canary —
  if it climbs steadily for a particular pod, that pod likely needs a
  restart. SNI tagging itself is bypassed if a sidecar proxy (Istio,
  Envoy) terminates TLS upstream of the workload.
- **Service-mesh TLS termination.** Same as above — when an in-cluster
  mesh sidecar handles TLS to the LLM provider, the workload itself
  doesn't open the provider connection, and the agent can only attribute
  the call to the sidecar process. There's no general workaround short
  of instrumenting the sidecar.
- **Body capture is bounded.** eBPF payload capture is limited per
  packet; very large request or response bodies may have token counts
  extracted only partially. Streaming responses use a 64 KB tail
  buffer that retains the end of the stream where token counts
  typically land.
- **Pricing is best-effort.** Prices in `containers/llm_pricing.go`
  reflect list rates at the time the entry was written and require
  manual updates. Models not in the table report cost = 0.
- **Google Gemini cannot be IP-tagged.** Because Google's anycast IP
  pool is shared across many services, IP-only detection would
  produce false positives. Detection requires SNI (TLS) or the
  `:authority` header (HTTP/2).
