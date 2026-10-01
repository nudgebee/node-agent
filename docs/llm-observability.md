# LLM observability

The agent identifies outbound calls to large-language-model APIs and
exposes per-request metrics: model, token usage, latency and
time-to-first-token, alongside the container, pod and namespace the
request came from. No code changes, SDK wrappers or proxies are needed:
the traffic is captured in eBPF on the node.

This feature is specific to this fork and is not present in upstream
`coroot/coroot-node-agent`.

## How it works

1. **Identification.** A connection is identified as an LLM API
   connection by the hostname in its TLS ClientHello (SNI), before any
   request is sent. Endpoints without a recognisable hostname — an LLM
   gateway or a self-hosted model server reached over plain HTTP — are
   identified by their API paths instead (`/v1/chat/completions`,
   `/v1/messages`, `:generateContent`, the Bedrock `/model/...` forms,
   and so on).
2. **Capture.** The agent marks the connection in the kernel. From then
   on every read and write on it is copied, in order, to userspace. For
   HTTPS this is the plaintext seen by the TLS library (Go `crypto/tls`
   or OpenSSL); the encrypted socket traffic of such connections is never
   parsed.
3. **Reassembly.** HTTP/1.1 and HTTP/2 exchanges are rebuilt from the
   byte stream with standard parsers, including chunked transfer,
   `gzip`/`deflate`/`zstd` content encoding, server-sent events and AWS
   event streams. Timings come from kernel timestamps.
4. **Usage.** The model and token counts are read from the response with
   typed decoders per wire format: OpenAI (chat, completions, embeddings,
   Responses API) and everything compatible with it, Anthropic, Gemini
   and Vertex AI, Bedrock (Converse, and InvokeModel via its token-count
   response headers, which every model returns), and Cohere.

## Supported providers

| Provider                | Identified by                                                           |
| ----------------------- | ----------------------------------------------------------------------- |
| OpenAI                  | `api.openai.com`                                                        |
| Azure OpenAI            | `<resource>.openai.azure.com`, `<resource>.services.ai.azure.com`       |
| Anthropic               | `api.anthropic.com`                                                     |
| Google Gemini           | `generativelanguage.googleapis.com`                                     |
| Google Vertex AI        | `aiplatform.googleapis.com`, `<region>-aiplatform.googleapis.com`       |
| AWS Bedrock             | `bedrock-runtime.<region>.amazonaws.com`                                |
| Cohere                  | `api.cohere.com`, `api.cohere.ai`                                       |
| DeepSeek, Groq, Mistral, Perplexity, xAI, Together, Fireworks | their API hostnames               |
| Gateways, self-hosted   | API paths of any of the above wire formats (`gen_ai_provider_name="openai_compatible"`) |

## Metrics

Every series carries `container_id`, `gen_ai_provider_name`,
`gen_ai_request_model`, `gen_ai_operation_name` and `server_address`.
Label names follow the OpenTelemetry GenAI semantic conventions.

| Metric                                      | Type      | Extra labels                |
| ------------------------------------------- | --------- | --------------------------- |
| `container_llm_requests_total`              | counter   | `http_response_status_code` |
| `container_llm_tokens_total`                | counter   | `gen_ai_token_type`         |
| `container_llm_request_duration_seconds`    | histogram |                             |
| `container_llm_time_to_first_token_seconds` | histogram | streaming responses only    |
| `node_agent_llm_capture_total`              | counter   | `outcome` (see below)       |

`gen_ai_token_type` is one of `input` (prompt tokens not served from a
cache), `cached_input`, `cache_write`, `output` (excluding reasoning) and
`reasoning`. The types are disjoint, so their sum is what the provider
bills, and each can be priced separately. Providers report overlapping
totals instead, and each wire format is normalised accordingly.

The agent does not compute cost. Join `container_llm_tokens_total` with
your own price list, which can reflect negotiated rates.

### Capture completeness

`node_agent_llm_capture_total{outcome}` accounts for what was and was
not captured:

| Outcome         | Meaning                                                                 |
| --------------- | ----------------------------------------------------------------------- |
| `tagged`        | a connection was identified and marked for capture                      |
| `completed`     | a request's usage was extracted                                         |
| `no_usage`      | the response carried no usage (an error, or a stream without it)        |
| `undecodable`   | the response used an unsupported content encoding (for example `br`)    |
| `truncated`     | the response body exceeded 8 MB                                         |
| `missed_start`  | capture began mid-connection (see *Limitations*)                        |
| `unrecoverable` | the protocol framing was lost                                           |
| `overflow`      | the parser fell behind the capture                                      |
| `capacity`      | a container had too many captured connections                           |

`node_agent_l7_tls_ciphertext_skipped_total` counts the encrypted socket
events the kernel skipped on TLS connections it already sees in plaintext.

## Sample queries

Tokens per model and type over the last hour:

```promql
sum by (gen_ai_request_model, gen_ai_token_type) (
  increase(container_llm_tokens_total[1h])
)
```

P95 time-to-first-token per provider:

```promql
histogram_quantile(0.95,
  sum by (gen_ai_provider_name, le) (
    rate(container_llm_time_to_first_token_seconds_bucket[5m])
  )
)
```

Share of requests whose usage was captured:

```promql
sum(rate(node_agent_llm_capture_total{outcome="completed"}[1h]))
/
sum(rate(node_agent_llm_capture_total{outcome=~"completed|no_usage|undecodable|truncated"}[1h]))
```

## Limitations

- **Connections opened before the agent.** An HTTPS connection that was
  already open when the agent started was never seen in its ClientHello,
  so it is not identified. HTTP/1.1 keep-alive connections are picked up
  by path detection at their next request; HTTP/2 ones cannot be decoded
  mid-connection at all, since their header compression state is unknown.
  Restart workloads after installing the agent to see all of their
  traffic. `missed_start` counts identified connections whose capture
  still began too late.
- **Streams without usage.** OpenAI-compatible streaming responses only
  carry usage when the client sets `stream_options.include_usage`.
  Without it the request, latency and time-to-first-token are recorded,
  but not tokens (`no_usage`).
- **TLS libraries.** Plaintext is captured for Go `crypto/tls` and
  dynamically linked OpenSSL (Python, Ruby, PHP, curl, .NET on Linux,
  and others). Java's JSSE, rustls, and runtimes that statically link
  their TLS library (Node.js, BoringSSL in Envoy) are not covered. An
  application that talks plain HTTP to a sidecar is captured through
  path detection.
- **gRPC transports** (for example Vertex AI's gRPC API) are not decoded.
- **Brotli** response encoding is not decoded (`undecodable`).
