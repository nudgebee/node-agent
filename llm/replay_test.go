package llm

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// The tests in this file drive real Go HTTP clients against local TLS servers,
// record the plaintext each client hands to and receives from crypto/tls —
// exactly what the kernel's TLS uprobes capture — and replay it into a Conn.
// The servers know the usage they reported, so extraction must match exactly.

type chunk struct {
	dir     Direction
	data    []byte
	ts      uint64
	skipped uint64
}

type recorder struct {
	mu     sync.Mutex
	chunks []chunk
}

func (r *recorder) add(dir Direction, p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.chunks = append(r.chunks, chunk{dir: dir, data: append([]byte(nil), p...), ts: uint64(time.Now().UnixNano())})
}

// recConn records plaintext at the crypto/tls boundary.
type recConn struct {
	net.Conn
	r *recorder
}

func (c *recConn) Write(p []byte) (int, error) {
	c.r.add(Egress, p)
	return c.Conn.Write(p)
}

func (c *recConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.r.add(Ingress, p[:n])
	}
	return n, err
}

func dialRecorded(srv *httptest.Server, rec *recorder, proto string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		cfg := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		cfg.NextProtos = []string{proto}
		cfg.ServerName = "example.com"
		tc := tls.Client(raw, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return &recConn{Conn: tc, r: rec}, nil
	}
}

func newServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// h2Client and h1Client both leave Accept-Encoding to the transport, which
// asks for gzip: the default behaviour of every Go program.
func h2Client(srv *httptest.Server, rec *recorder) *http.Client {
	return &http.Client{Transport: &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return dialRecorded(srv, rec, "h2")(ctx, network, addr)
		},
	}}
}

func h1Client(srv *httptest.Server, rec *recorder) *http.Client {
	return &http.Client{Transport: &http.Transport{DialTLSContext: dialRecorded(srv, rec, "http/1.1")}}
}

// replay feeds recorded chunks into a Conn and returns the exchanges it
// produced. maxChunk, when non-zero, mimics the kernel's per-event capture
// limit: the rest of a larger chunk is reported as skipped.
func replay(t *testing.T, rec *recorder, maxChunk int, from int) ([]*Exchange, []Outcome) {
	t.Helper()
	var mu sync.Mutex
	var exchanges []*Exchange
	var outcomes []Outcome
	c := NewConn(Tag{Provider: ProviderGemini, Host: "example.com"},
		func(e *Exchange) { mu.Lock(); exchanges = append(exchanges, e); mu.Unlock() },
		func(o Outcome) { mu.Lock(); outcomes = append(outcomes, o); mu.Unlock() })
	rec.mu.Lock()
	chunks := append([]chunk(nil), rec.chunks...)
	rec.mu.Unlock()
	var pendingSkip [2]uint64
	for _, ch := range chunks[from:] {
		data := ch.data
		skip := pendingSkip[ch.dir]
		pendingSkip[ch.dir] = 0
		if maxChunk > 0 && len(data) > maxChunk {
			pendingSkip[ch.dir] = uint64(len(data) - maxChunk)
			data = data[:maxChunk]
		}
		c.Feed(ch.dir, data, ch.ts, skip)
		// A trailing skip is reported with the next chunk in that direction,
		// as the kernel does. Flush it now if this was the last one.
	}
	for dir, skip := range pendingSkip {
		if skip > 0 {
			c.Feed(Direction(dir), nil, uint64(time.Now().UnixNano()), skip)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(exchanges)
		mu.Unlock()
		if n > 0 {
			time.Sleep(50 * time.Millisecond) // let stragglers finish
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	c.Close()
	mu.Lock()
	defer mu.Unlock()
	return exchanges, outcomes
}

func gzipWriter(w http.ResponseWriter, r *http.Request) (io.Writer, func()) {
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		return w, func() {}
	}
	w.Header().Set("Content-Encoding", "gzip")
	gz := gzip.NewWriter(w)
	return gz, func() { _ = gz.Close() }
}

func flush(w http.ResponseWriter, out io.Writer) {
	if gz, ok := out.(*gzip.Writer); ok {
		_ = gz.Flush()
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// geminiStream streams usageMetadata cumulatively, as Gemini does, with the
// final totals in the last event.
func geminiStream(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	w.Header().Set("Content-Type", "text/event-stream")
	out, done := gzipWriter(w, r)
	defer done()
	for i := 1; i <= 5; i++ {
		ev := fmt.Sprintf(`{"candidates":[{"content":{"parts":[{"text":"chunk %d %s"}]}}],"usageMetadata":{"promptTokenCount":1200,"candidatesTokenCount":%d,"cachedContentTokenCount":800,"thoughtsTokenCount":40},"modelVersion":"gemini-test-flash"}`, i, strings.Repeat("x", 300), i*10)
		_, _ = fmt.Fprintf(out, "data: %s\r\n\r\n", ev)
		flush(w, out)
		time.Sleep(2 * time.Millisecond)
	}
}

func TestReplayGeminiStreamingHTTP2Gzip(t *testing.T) {
	srv := newServer(t, geminiStream)
	rec := &recorder{}
	client := h2Client(srv, rec)

	// A large prompt and several concurrent streams on one connection: the
	// shape of real traffic, and what desynchronised the old parser.
	prompt := strings.Repeat(`{"text":"lorem ipsum dolor sit amet"},`, 8000)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Post(srv.URL+"/v1beta/models/gemini-test-flash:streamGenerateContent?alt=sse",
				"application/json", strings.NewReader(`{"contents":[`+prompt+`{}]}`))
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()

	for _, maxChunk := range []int{0, 16 << 10} {
		exchanges, outcomes := replay(t, rec, maxChunk, 0)
		if len(outcomes) != 0 {
			t.Fatalf("maxChunk=%d: unexpected connection outcomes %v", maxChunk, outcomes)
		}
		if len(exchanges) != 4 {
			t.Fatalf("maxChunk=%d: got %d exchanges, want 4", maxChunk, len(exchanges))
		}
		for _, e := range exchanges {
			want := Usage{Input: 400, CachedInput: 800, Output: 50, Reasoning: 40}
			if e.Outcome != OutcomeCompleted || e.Usage != want {
				t.Errorf("maxChunk=%d: outcome=%s usage=%+v, want completed %+v", maxChunk, e.Outcome, e.Usage, want)
			}
			if e.Model != "gemini-test-flash" || e.Operation != OperationGenerate || !e.Streaming || e.StatusCode != 200 {
				t.Errorf("maxChunk=%d: model=%q op=%q streaming=%v status=%d", maxChunk, e.Model, e.Operation, e.Streaming, e.StatusCode)
			}
			if e.TimeToFirstToken() <= 0 || e.Duration() < e.TimeToFirstToken() {
				t.Errorf("maxChunk=%d: ttft=%s duration=%s", maxChunk, e.TimeToFirstToken(), e.Duration())
			}
		}
	}
}

func openAIChat(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	stream := bytes.Contains(body, []byte(`"stream":true`))
	out, done := gzipWriter(w, r)
	defer done()
	if !stream {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(out, `{"id":"c1","object":"chat.completion","model":"gpt-test-2026","choices":[{"message":{"role":"assistant","content":"`+strings.Repeat("y", 6000)+`"}}],"usage":{"prompt_tokens":1000,"completion_tokens":300,"total_tokens":1300,"prompt_tokens_details":{"cached_tokens":600},"completion_tokens_details":{"reasoning_tokens":100}}}`)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	for i := 0; i < 3; i++ {
		_, _ = io.WriteString(out, `data: {"model":"gpt-test-2026","choices":[{"delta":{"content":"hi"}}],"usage":null}`+"\n\n")
		flush(w, out)
	}
	_, _ = io.WriteString(out, `data: {"model":"gpt-test-2026","choices":[],"usage":{"prompt_tokens":50,"completion_tokens":7,"total_tokens":57}}`+"\n\n")
	_, _ = io.WriteString(out, "data: [DONE]\n\n")
	flush(w, out)
}

func TestReplayOpenAIHTTP1(t *testing.T) {
	srv := newServer(t, openAIChat)
	rec := &recorder{}
	client := h1Client(srv, rec)
	for _, body := range []string{
		`{"messages":[{"role":"user","content":"` + strings.Repeat("p", 100000) + `"}],"model":"gpt-test"}`,
		`{"messages":[],"model":"gpt-test","stream":true,"stream_options":{"include_usage":true}}`,
	} {
		resp, err := client.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	for _, maxChunk := range []int{0, 16 << 10} {
		exchanges, outcomes := replay(t, rec, maxChunk, 0)
		if len(outcomes) != 0 || len(exchanges) != 2 {
			t.Fatalf("maxChunk=%d: exchanges=%d outcomes=%v", maxChunk, len(exchanges), outcomes)
		}
		if got, want := exchanges[0].Usage, (Usage{Input: 400, CachedInput: 600, Output: 200, Reasoning: 100}); got != want || exchanges[0].Streaming {
			t.Errorf("non-streaming: usage=%+v streaming=%v, want %+v", got, exchanges[0].Streaming, want)
		}
		if got, want := exchanges[1].Usage, (Usage{Input: 50, Output: 7}); got != want || !exchanges[1].Streaming {
			t.Errorf("streaming: usage=%+v streaming=%v, want %+v", got, exchanges[1].Streaming, want)
		}
		for _, e := range exchanges {
			if e.Model != "gpt-test-2026" || e.Operation != OperationChat || e.Outcome != OutcomeCompleted {
				t.Errorf("model=%q op=%q outcome=%s", e.Model, e.Operation, e.Outcome)
			}
		}
	}
}

func anthropicStream(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	w.Header().Set("Content-Type", "text/event-stream")
	events := []string{
		`event: message_start` + "\n" + `data: {"type":"message_start","message":{"model":"claude-test","usage":{"input_tokens":20,"cache_creation_input_tokens":300,"cache_read_input_tokens":1000,"output_tokens":1}}}`,
		`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}`,
		`event: message_delta` + "\n" + `data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":42}}`,
		`event: message_stop` + "\n" + `data: {"type":"message_stop"}`,
	}
	for _, ev := range events {
		_, _ = io.WriteString(w, ev+"\n\n")
		flush(w, w)
	}
}

func TestReplayAnthropicStreamingHTTP2(t *testing.T) {
	srv := newServer(t, anthropicStream)
	rec := &recorder{}
	resp, err := h2Client(srv, rec).Post(srv.URL+"/v1/messages", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	exchanges, _ := replay(t, rec, 0, 0)
	if len(exchanges) != 1 {
		t.Fatalf("got %d exchanges", len(exchanges))
	}
	e := exchanges[0]
	if want := (Usage{Input: 20, CachedInput: 1000, CacheWrite: 300, Output: 42}); e.Usage != want || e.Model != "claude-test" {
		t.Errorf("usage=%+v model=%q, want %+v claude-test", e.Usage, e.Model, want)
	}
}

// eventStreamMessage encodes one AWS event-stream message.
func eventStreamMessage(eventType string, payload []byte) []byte {
	var headers bytes.Buffer
	for _, h := range [][2]string{{":message-type", "event"}, {":event-type", eventType}, {":content-type", "application/json"}} {
		headers.WriteByte(byte(len(h[0])))
		headers.WriteString(h[0])
		headers.WriteByte(7)
		_ = binary.Write(&headers, binary.BigEndian, uint16(len(h[1])))
		headers.WriteString(h[1])
	}
	total := 12 + headers.Len() + len(payload) + 4
	var msg bytes.Buffer
	_ = binary.Write(&msg, binary.BigEndian, uint32(total))
	_ = binary.Write(&msg, binary.BigEndian, uint32(headers.Len()))
	_ = binary.Write(&msg, binary.BigEndian, crc32.ChecksumIEEE(msg.Bytes()[:8]))
	msg.Write(headers.Bytes())
	msg.Write(payload)
	_ = binary.Write(&msg, binary.BigEndian, crc32.ChecksumIEEE(msg.Bytes()))
	return msg.Bytes()
}

func bedrock(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	switch {
	case strings.HasSuffix(r.URL.Path, "/converse-stream"):
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		_, _ = w.Write(eventStreamMessage("contentBlockDelta", []byte(`{"delta":{"text":"hi"}}`)))
		_, _ = w.Write(eventStreamMessage("metadata", []byte(`{"usage":{"inputTokens":120,"outputTokens":30,"cacheReadInputTokens":500,"cacheWriteInputTokens":0},"metrics":{"latencyMs":80}}`)))
	case strings.HasPrefix(r.URL.Path, "/model/mistral."):
		// A model whose body reports no usage: only the headers have it.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Amzn-Bedrock-Input-Token-Count", "33")
		w.Header().Set("X-Amzn-Bedrock-Output-Token-Count", "12")
		_, _ = io.WriteString(w, `{"outputs":[{"text":"hi","stop_reason":"stop"}]}`)
	case strings.HasSuffix(r.URL.Path, "/invoke"):
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Amzn-Bedrock-Input-Token-Count", "9")
		w.Header().Set("X-Amzn-Bedrock-Output-Token-Count", "0")
		embedding, _ := json.Marshal(make([]float64, 1024))
		_, _ = fmt.Fprintf(w, `{"embedding":%s,"inputTextTokenCount":9}`, embedding)
	}
}

func TestReplayBedrockHTTP1(t *testing.T) {
	srv := newServer(t, bedrock)
	rec := &recorder{}
	client := h1Client(srv, rec)
	for _, path := range []string{
		"/model/us.anthropic.claude-test-v1%3A0/converse-stream",
		"/model/amazon.titan-embed-text-v2:0/invoke",
		"/model/mistral.mistral-test/invoke",
	} {
		resp, err := client.Post(srv.URL+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	exchanges, outcomes := replay(t, rec, 0, 0)
	if len(exchanges) != 3 || len(outcomes) != 0 {
		t.Fatalf("exchanges=%d outcomes=%v", len(exchanges), outcomes)
	}
	if e := exchanges[0]; e.Usage != (Usage{Input: 120, CachedInput: 500, Output: 30}) || e.Model != "us.anthropic.claude-test-v1:0" || e.Operation != OperationChat || !e.Streaming {
		t.Errorf("converse-stream: usage=%+v model=%q op=%q streaming=%v", e.Usage, e.Model, e.Operation, e.Streaming)
	}
	if e := exchanges[1]; e.Usage != (Usage{Input: 9}) || e.Model != "amazon.titan-embed-text-v2:0" || e.Operation != OperationEmbeddings {
		t.Errorf("titan invoke: usage=%+v model=%q op=%q", e.Usage, e.Model, e.Operation)
	}
	if e := exchanges[2]; e.Usage != (Usage{Input: 33, Output: 12}) || e.Outcome != OutcomeCompleted {
		t.Errorf("header-only invoke: usage=%+v outcome=%s", e.Usage, e.Outcome)
	}
}

// A capture that starts mid-connection must be reported, not misparsed.
func TestReplayHTTP2MidStreamIsMissedStart(t *testing.T) {
	srv := newServer(t, geminiStream)
	rec := &recorder{}
	client := h2Client(srv, rec)
	for i := 0; i < 2; i++ {
		resp, err := client.Post(srv.URL+"/v1beta/models/gemini-test-flash:streamGenerateContent?alt=sse", "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	// Start after the first request's egress chunks.
	from := 0
	for i, ch := range rec.chunks {
		if ch.dir == Ingress {
			from = i
			break
		}
	}
	for from < len(rec.chunks) && rec.chunks[from].dir != Egress {
		from++
	}
	exchanges, outcomes := replay(t, rec, 0, from)
	if len(exchanges) != 0 {
		t.Errorf("got %d exchanges from a mid-stream capture, want 0", len(exchanges))
	}
	if len(outcomes) != 1 || outcomes[0] != OutcomeMissedStart {
		t.Errorf("outcomes=%v, want [missed_start]", outcomes)
	}
}

// HTTP/1.1 recovers when capture starts mid-connection: the requests after
// the first one are reassembled in full.
func TestReplayHTTP1MidStreamRecovers(t *testing.T) {
	srv := newServer(t, openAIChat)
	rec := &recorder{}
	client := h1Client(srv, rec)
	for i := 0; i < 3; i++ {
		body := `{"model":"gpt-test"}`
		if i == 0 {
			body = `{"model":"gpt-test","messages":[{"content":"` + strings.Repeat("p", 200000) + `"}]}`
		}
		resp, err := client.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	// Start in the middle of the first request's body.
	from := -1
	for i, ch := range rec.chunks {
		if i > 0 && ch.dir == Egress && rec.chunks[i-1].dir == Egress {
			from = i
			break
		}
	}
	if from < 0 {
		t.Fatal("first request was not split across writes")
	}
	exchanges, outcomes := replay(t, rec, 0, from)
	if len(outcomes) != 1 || outcomes[0] != OutcomeMissedStart {
		t.Errorf("outcomes=%v, want [missed_start]", outcomes)
	}
	if len(exchanges) != 2 {
		t.Fatalf("got %d exchanges, want 2", len(exchanges))
	}
	for _, e := range exchanges {
		if e.Outcome != OutcomeCompleted || e.Usage.Output != 200 {
			t.Errorf("outcome=%s usage=%+v", e.Outcome, e.Usage)
		}
	}
}

// A client that opens a connection per request (Connection: close) to a
// streaming endpoint: the shape of an in-cluster gateway client.
func TestReplayHTTP1ConnectionClosePerRequest(t *testing.T) {
	srv := newServer(t, openAIChat)
	for i := 0; i < 3; i++ {
		rec := &recorder{}
		client := &http.Client{Transport: &http.Transport{DialTLSContext: dialRecorded(srv, rec, "http/1.1"), DisableKeepAlives: true}}
		resp, err := client.Post(srv.URL+"/v1/chat/completions", "application/json",
			strings.NewReader(`{"model":"gpt-test","stream":true,"stream_options":{"include_usage":true},"messages":[{"content":"`+strings.Repeat("q", 38000)+`"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		exchanges, outcomes := replay(t, rec, 64<<10, 0)
		if len(exchanges) != 1 || len(outcomes) != 0 {
			t.Fatalf("exchanges=%d outcomes=%v", len(exchanges), outcomes)
		}
		if e := exchanges[0]; e.Outcome != OutcomeCompleted || e.Usage.Output != 7 {
			t.Errorf("outcome=%s usage=%+v", e.Outcome, e.Usage)
		}
	}
}

// A client that cancels a stream mid-response sends RST_STREAM; the server
// never finishes it. The request must still be reported, not leak.
func TestReplayHTTP2ClientCancel(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < 50; i++ {
			_, _ = io.WriteString(w, `data: {"candidates":[{"content":{"parts":[{"text":"x"}]}}]}`+"\r\n\r\n")
			flush(w, w)
			select {
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	})
	rec := &recorder{}
	client := h2Client(srv, rec)
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+"/v1beta/models/gemini-test-flash:streamGenerateContent?alt=sse", strings.NewReader(`{}`))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_, _ = resp.Body.Read(buf)
	cancel()
	_ = resp.Body.Close()
	time.Sleep(100 * time.Millisecond)
	exchanges, _ := replay(t, rec, 0, 0)
	if len(exchanges) != 1 {
		t.Fatalf("got %d exchanges, want 1", len(exchanges))
	}
	if e := exchanges[0]; e.Model != "gemini-test-flash" || e.Outcome != OutcomeNoUsage {
		t.Errorf("model=%q outcome=%s", e.Model, e.Outcome)
	}
}

// A plaintext gateway client: HTTP/1.1 over plain TCP, a 38KB request, a
// large SSE response streamed in many small writes, recorded at the socket.
func TestReplayPlaintextGatewayLargeStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < 600; i++ {
			_, _ = fmt.Fprintf(w, "data: {\"model\":\"qwen-test\",\"choices\":[{\"delta\":{\"content\":%q}}],\"usage\":null}\n\n", strings.Repeat("t", 350))
			if i%20 == 0 {
				w.(http.Flusher).Flush()
			}
		}
		_, _ = io.WriteString(w, `data: {"model":"qwen-test","choices":[],"usage":{"prompt_tokens":9000,"completion_tokens":600,"total_tokens":9600}}`+"\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()
	for _, keepAlive := range []bool{true, false} {
		rec := &recorder{}
		client := &http.Client{Transport: &http.Transport{
			DisableKeepAlives: !keepAlive,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				return &recConn{Conn: c, r: rec}, nil
			},
		}}
		resp, err := client.Post(srv.URL+"/v1/chat/completions", "application/json",
			strings.NewReader(`{"model":"qwen-test","stream":true,"messages":[{"content":"`+strings.Repeat("q", 38000)+`"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		client.CloseIdleConnections()
		exchanges, outcomes := replay(t, rec, 65535, 0)
		if len(exchanges) != 1 || len(outcomes) != 0 {
			t.Fatalf("keepAlive=%v: exchanges=%d outcomes=%v chunks=%d", keepAlive, len(exchanges), outcomes, len(rec.chunks))
		}
		if e := exchanges[0]; e.Outcome != OutcomeCompleted || e.Usage.Input != 9000 || e.Usage.Output != 600 {
			t.Errorf("keepAlive=%v: outcome=%s usage=%+v", keepAlive, e.Outcome, e.Usage)
		}
	}
}

// A connection closed with a request in flight is reported as abandoned, and
// the outcome callback may inspect the connection's stats without deadlock.
func TestAbandonedReportsStats(t *testing.T) {
	var c *Conn
	got := make(chan Stats, 1)
	c = NewConn(Tag{}, nil, func(o Outcome) {
		if o == OutcomeAbandoned {
			got <- c.Stats()
		}
	})
	c.Feed(Egress, []byte("POST /v1/chat/completions HTTP/1.1\r\nHost: gw\r\nContent-Length: 2\r\n\r\n{}"), 1, 0)
	c.Close()
	select {
	case st := <-got:
		if st.FirstIngress || st.Bytes[Egress] == 0 || !bytes.HasPrefix(st.Head[Egress], []byte("POST ")) {
			t.Errorf("stats=%+v", st)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no abandoned outcome (or deadlock)")
	}
}
