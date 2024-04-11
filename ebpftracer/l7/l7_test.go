package l7

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
)

func TestParseHttp(t *testing.T) {
	m, p := ParseHttp([]byte(`HEAD /1 HTTP/1.1\nHost: 127.0.0.1\nUser-Agent: curl/8.0.1\nAccept: */*\n\nxzxxxxxxzx`))
	assert.Equal(t, "HEAD", m)
	assert.Equal(t, "/1", p)

	m, p = ParseHttp([]byte(`GET /too-long-uri`))
	assert.Equal(t, "GET", m)
	assert.Equal(t, "/too-long-uri...", p)
}

func Test_parseMemcached(t *testing.T) {
	cmd, items := ParseMemcached(append([]byte(`incr 1111 2222`), '\r', '\n'))
	assert.Equal(t, "incr", cmd)
	assert.Equal(t, []string{"1111"}, items)

	cmd, items = ParseMemcached(append([]byte(`gets 1111 2222 3333`), '\r', '\n'))
	assert.Equal(t, "gets", cmd)
	assert.Equal(t, []string{"1111", "2222", "3333"}, items)
}

func TestParseRedis(t *testing.T) {
	cmd, args := ParseRedis([]byte{
		'*', '3', '\r', '\n',
		'$', '4', '\r', '\n',
		'L', 'L', 'E', 'N', '\r', '\n',
		'$', '6', '\r', '\n',
		'm', 'y', 'l', 'i', 's', 't', '\r', '\n',
		'$', '2', '\r', '\n',
		'x', 'y', '\r', '\n',
	})
	assert.Equal(t, "LLEN", cmd)
	assert.Equal(t, "mylist ...", args)

	cmd, args = ParseRedis([]byte{
		'*', '2', '\r', '\n',
		'$', '8', '\r', '\n',
		'S', 'M', 'E', 'M', 'B', 'E', 'R', 'S', '\r', '\n',
		'$', '6', '\r', '\n',
		'm', 'y', 'l', 'i', 's', 't', '\r', '\n',
	})

	assert.Equal(t, "SMEMBERS", cmd)
	assert.Equal(t, "mylist", args)
}

type mongoHeader struct {
	MessageLength int32
	RequestID     int32
	ResponseTo    int32
	OpCode        int32
	Flags         int32
	SectionKind   uint8
}

func TestParseMongo(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	v := bson.M{"a": "bssssssssssssssssssssssssssssssssssssssssss"}
	data, err := bson.Marshal(v)
	assert.NoError(t, err)

	h := mongoHeader{
		MessageLength: 16 + 4 + 1 + int32(len(data)),
		OpCode:        MongoOpMSG,
	}

	assert.NoError(t, binary.Write(buf, binary.LittleEndian, h))
	_, err = buf.Write(data)
	assert.NoError(t, err)

	payload := buf.Bytes()

	assert.Equal(t, `{"a": "bssssssssssssssssssssssssssssssssssssssssss"}`, ParseMongo(payload))
	assert.Equal(t, `<truncated>`, ParseMongo(payload[:20]))

	dataSize := binary.LittleEndian.Uint32(data)

	binary.LittleEndian.PutUint32(payload[mongoHeaderLength+mongoSectionKindLength:], dataSize+1)
	assert.Equal(t, `<truncated>`, ParseMongo(payload))
}

func TestParseHost(t *testing.T) {
	requestString := "HEAD /1 HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: curl/8.0.1\r\nAccept: */*\r\n\r\nxzxxxxxxzx"
	req, err := ParseHTTPRequest([]byte(requestString))
	assert.Nil(t, nil, err)
	assert.Equal(t, "/1", req.URL.Path)
	assert.Equal(t, "127.0.0.1", req.Host)
	assert.Equal(t, "HEAD", req.Method)
	body, err := io.ReadAll(req.Body)
	assert.Nil(t, nil, err)
	assert.Equal(t, "xzxxxxxxzx", string(body))

	headers := ConvertHeadersToString(req.Header)
	assert.NotNil(t, headers)

	requestString = "POST / HTTP/1.1\r\nHost: ec2.us-east-1.amazonaws.com\r\nUser-Agent: aws-sdk-go/1.50.10 (go1.21.6; linux; amd64) karpenter.sh-v0.34.0\r\nContent-Length: 422\r\nAuthorization: AWS4-HMAC-SHA256 Credential=ASIAUCTZOIG67J6IJFOY/20240408/us-east-1/ec2/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-security-token, Signature=3d7eadceec976dd17fbdcc07ae43a75264baf179fec70c6aa2be7411fd552e70\r\nContent-Type: application/x-www-form-urlencoded; charset=utf-8\r\nX-Amz-Date: 20240408T094330Z\r\nX-Amz-Security-Token: IQoJb3JpZ2luX2VjEML//////////wEaCXVzLWVhc3QtMSJHMEUCIB8pKvU76WFQ99xqZH8LQXhOBfCP/lhnMSkmIp1LcvLEAiEAk3XkJCPMFGQC4KqMk92boxaeNHiLvbinmW9AQgEGnBcq/gQI6///////////ARABGgwyODA1MDEzMDU3ODkiDJA/sBIYp1t0z9szDirSBPDDQ+mKiBwDvCwqZ/HH9wSh9U6WKYjh0EPX9i3cHE46oee4CAUoQwEmDy9xZp02UZcpOjiDF6iaKyOvi93+LoiwJVBNi53o/PnMoStfI4OmG4Rc61YYcPc6t6SSXeBEGCzeeesWAGBDJ6GE2PWYYQAKS3YrpxYE+UKdb4hxEBO5t8RgEO/ooiHehFC/5VSmjMeMfT/XMdmAxBplX/wCMoz2vMcpkCi3fCsX0RNjxT7bAO/D2jOUrIX8UjM38h2VGNliSfCl8B3HbCETxYiz66AhMGabknMpJ8Dcotm\x00"
	req, err = ParseHTTPRequest([]byte(requestString))
	assert.Nil(t, nil, err)
	assert.Equal(t, "/", req.URL.Path)
	assert.Equal(t, "ec2.us-east-1.amazonaws.com", req.Host)
	assert.Equal(t, "POST", req.Method)

	headers = ConvertHeadersToString(req.Header)
	assert.NotNil(t, headers)

	requestString = "POST / HTTP/1.1\r\nHost: ec2.us-east-1.amazonaws.com\r\nUser-Agent: aws-sdk-go/1.50.10 (go1.21.6; linux; amd64) karpenter.sh-v0.34.0\r\nContent-Length: 422\r\nAuthorization: AWS4-HMAC-SHA256 Credential=ASIAUCTZOIG67J6IJFOY/20240408/us-east-1/ec2/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-security-token, Signature=3d7eadceec976dd17fbdcc07ae43a75264baf179fec70c6aa2be7411fd552e70\r\nContent-Type: application/x-www-form-urlencoded; charset=utf-8\r\nX-Amz-Date: 20240408T094330Z\r\nX-Amz-Security-Token: IQoJb3JpZ2luX2VjEML//////////wEaCXVzLWVhc3QtMSJHMEUCIB8pKvU76WFQ99xqZH8LQXhOBfCP/lhnMSkmIp1LcvLEAiEAk3XkJCPMFGQC4KqMk92boxaeNHiLvbinmW9AQgEGnBcq/gQI6///////////ARABGgwyODA1MDEzMDU3ODkiDJA/sBIYp1t0z9szDirSBPDDQ+mKiBwDvCwqZ/HH9wSh9U6WKYjh0EPX9i3cHE46oee4CAUoQwEmDy9xZp02UZcpOjiDF6iaKyOvi93+LoiwJVBNi53o/PnMoStfI4OmG4Rc61YYcPc6t6SSXeBEGCzeeesWAGBDJ6GE2PWYYQAKS3YrpxYE+UKdb4hxEBO5t8RgEO/ooiHehFC/5VSmjMeMfT/XMdmAxBplX/wCMoz2vMcpkCi3fCsX0RNjxT7bAO/D2jOUrIX8UjM38h2VGNliSfCl8B3HbCETxYiz66AhMGabknMpJ8Dcotm\x00"
	req, err = ParseHTTPRequest([]byte(requestString))
	assert.Nil(t, nil, err)
	assert.Equal(t, "/", req.URL.Path)
	assert.Equal(t, "ec2.us-east-1.amazonaws.com", req.Host)
	assert.Equal(t, "POST", req.Method)

	headers = ConvertHeadersToString(req.Header)
	assert.NotNil(t, headers)

	requestString = "GET /api/v1/namespaces/nudgebee-agent/pods/nudgebee-agent-pgnxh/log?container=node-agent&previous=False&tailLines=1000&timestamps=True HTTP/1.1\r\nHost: 10.100.0.1\r\nAccept-Encoding: identity\r\nAccept: application/json\r\nUser-Agent: OpenAPI-Generator/26.1.0/python\r\nauthorization: bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjNhZTFlNjlkN2I1ZmFkNzhhNTg2YTVjN2JmMDNjOGU3YjUzNGI4N2MifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjIl0sImV4cCI6MTc0NDEwMjY0OSwiaWF0IjoxNzEyNTY2NjQ5LCJpc3MiOiJodHRwczovL29pZGMuZWtzLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tL2lkL0I4RkU4OUQ4MjdEN0Q2RTE0REIyMUMzRkIwQTk1Q0E3Iiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJudWRnZWJlZS1hZ2VudCIsInBvZCI6eyJuYW1lIjoibnVkZ2ViZWUtYWdlbnQtcnVubmVyLTZiZmY2NmQ3YjgtcWttbmwiLCJ1aWQiOiJiN2M4ZGM2NC04Y2Q0LTRiMWUtODg1Zi00YWMzMWE4NDYwMWIifSwic2VydmljZWFjY291bnQiOnsibmFtZSI6Im51ZGdlYmVlLWFnZW50LXJ1bm5lci1zZXJ2aWNlLWFjY291bnQiLCJ1aWQiOiJjODUzMDc2YS1hODVkLTQzYzItOWU3NS00MTk5ODIzMTVjOGIifSwid2FybmFmdGVyIjoxNzEyNTcwMjU2fSwibmJmIjoxNzEyNTY2NjQ5LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6b\x00"
	req, err = ParseHTTPRequest([]byte(requestString))
	assert.Nil(t, nil, err)
	assert.Equal(t, "/api/v1/namespaces/nudgebee-agent/pods/nudgebee-agent-pgnxh/log", req.URL.Path)
	assert.Equal(t, "10.100.0.1", req.Host)
	assert.Equal(t, "GET", req.Method)

	headers = ConvertHeadersToString(req.Header)
	assert.NotNil(t, headers)

	requestString = "PUT /nudgebee-dev-loki-logs/fake/ece64b2028d30d33/18ebcc10d27%3A18ebcfd01d3%3A3377d9aa HTTP/1.1\r\nHost: s3.amazonaws.com\r\nUser-Agent: aws-sdk-go/1.44.315 (go1.21.3; linux; amd64)\r\nContent-Length: 14183\r\nAuthorization: AWS4-HMAC-SHA256 Credential=ASIAUCTZOIG62SVE2F5J/20240408/us-east-1/s3/aws4_request, SignedHeaders=content-length;content-md5;host;x-amz-content-sha256;x-amz-date;x-amz-security-token;x-amz-storage-class, Signature=a4db153ba7127721c3a5efbbab1a0e194e473d23147a472c92ff672d9dff160c\r\nContent-Md5: VBSxwLVjCvMeC+z4V86k8A==\r\nX-Amz-Content-Sha256: fe19171172133fadb236229e71a8f60169fc5268da749b1eeeeb3396e7d90f64\r\nX-Amz-Date: 20240408T094454Z\r\nX-Amz-Security-Token: IQoJb3JpZ2luX2VjEL3//////////wEaCXVzLWVhc3QtMSJGMEQCIAvNhx/LC+nIkqUC+rRD3MOFuxr39bc+qmRwVPljywxuAiA/8bmpr+kmRy7zXBzBQ7eyayLftqLutyGrzu8TIZWVbyrGBQjm//////////8BEAEaDDI4MDUwMTMwNTc4OSIMRsng8zavN9ilo6+0KpoFc/pdelkZBjWQle/CNG4XKcnd9WFbu87JAB3xa1P97vfIBjhqpmHoPk4V38r21Vepl0NjeUnWahJA6NnOWW2mdhRv51+WGUmKSHz1j6NCRcC8axDXs65jJzF6WgqCGZGNa0aiUQP7oIGGV8\x00"
	req, err = ParseHTTPRequest([]byte(requestString))
	assert.Nil(t, nil, err)
	assert.Equal(t, "/nudgebee-dev-loki-logs/fake/ece64b2028d30d33/18ebcc10d27:18ebcfd01d3:3377d9aa", req.URL.Path)
	assert.Equal(t, "s3.amazonaws.com", req.Host)
	assert.Equal(t, "PUT", req.Method)

	headers = ConvertHeadersToString(req.Header)
	assert.NotNil(t, headers)

	requestString = "POST /api/v1/write HTTP/1.1\r\nHost: vmsingle-victoria-victoria-metrics-k8s-stack.victoria.svc:8429\r\nUser-Agent: vmagent\r\nContent-Length: 282715\r\nContent-Encoding: snappy\r\nContent-Type: application/x-protobuf\r\nX-Prometheus-Remote-Write-Version: 0.1.0\r\nAccept-Encoding: gzip\r\n\r\n\x91\x9b\xdc\x01\xb0\n\xe4\f\n$\n\b__name__\x12\x18container_memory_failcnt\n$\n\t\x15\x1c\xd0\x12\x17nudgebee-agent-opencost\n;\n\x05image\x122quay.io/kubecost1\x15\n\x00-\x01*X-model:prod-1.108.0\n\x1b\n\t\x01\x87\x18space\x12\x0e6c\x00 \n/\n\x03pod\x12(6\x17\x00\x15z\xd8-55b677fb47-87mz4\n \n\x17beta_kubernetes_io_arch\x12\x05amd64\n.\n J\"\x00pinstance_type\x12\nm5ad.large\n\x1e\n\x15J0\x00\xf0Cos\x12\x05linux\n&\n\x1eeks_amazonaws_com_capacityType\x12\x04SPOT\n5\n(failure_domain_JW\x00Pregion\x12\tus-east-1\n4\n&\x867\x00\x14zone\x12\n\x155\x10a\n(\n\b\x11Ҙ\x12\x1cip-172-31-0-236.ec2.internal\n\x0e\n\x03job\x12\a!1 let\n=\n\x19k8%5\xf0<cloud_provider_aws\x12 ed58b207ac78b478c91e5b775a4f8540\n(\n#karpe\x01_\x00_\x01I!\x12\x11\x8b@_category\x12\x01m\n#\n\x1ekj*\x00 pu\x12\x012\nC\n:j%\x00\xa8encryption_in_transit_supported\x12\x05false\n)\n!kfj\x00\x1cfamily\x12\x04!\xf3\f\n*\n%jp\x00\x14genera\x01p\x10\x12\x015\n.r,\x00Hhypervisor\x12\x05nitro\n+r0\x008local_nvme\x12\x0275\nv\xb4\x00i\xa6$\x12\x048192\n3\n,j\xb4\x00Pnetwork_bandwidth\x12\x0375!\xa8\x00\x1fj5\x00\x14size\x12\x05i\x00\b\"\n\x1a\x19*\x04shU\xdbi* \x04spot\n \n\x182$\x00Pinitializ\x00\x12@3c"
	req, err = ParseHTTPRequest([]byte(requestString))
	assert.Nil(t, nil, err)
	assert.Equal(t, "/api/v1/write", req.URL.Path)
	assert.Equal(t, "vmsingle-victoria-victoria-metrics-k8s-stack.victoria.svc:8429", req.Host)
	assert.Equal(t, "POST", req.Method)

	headers = ConvertHeadersToString(req.Header)
	assert.NotNil(t, headers)

	requestString = "GET /_next/static/css/5ecbfdce0834333a.css HTTP/1.1\r\nHost: test.nudgebee.pollux.in\r\nX-Request-ID: 521e623dfebcd7d7a102f151a1120be7\r\nX-Real-IP: 172.31.82.142\r\nX-Forwarded-For: 172.31.82.142\r\nX-Forwarded-Host: test.nudgebee.pollux.in\r\nX-Forwarded-Port: 443\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Scheme: https\r\nX-Scheme: https\r\nsec-ch-ua: \"Google Chrome\";v=\"123\", \"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"123\"\r\nsec-ch-ua-mobile: ?0\r\nuser-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36\r\nsec-ch-ua-platform: \"macOS\"\r\naccept: */*\r\nsec-fetch-site: same-origin\r\nsec-fetch-mode: cors\r\nsec-fetch-dest: empty\r\nreferer: https://test.nudgebee.pollux.in/home?accountId=6048794f-73c7-430a-a308-4d76f1b3b1e8\r\naccept-encoding: gzip, deflate, br, zstd\r\naccept-language: en-US,en;q=0.9\r\ncookie: cw_conversation=eyJhbGciOiJIUzI1NiJ9.eyJzb3VyY2VfaWQiOiJjZGZmNDkwMi0zNTZlLTRhMzYtOWUwNS0yYzcwNjNjNzA3MGIiLCJpbmJveF9pZCI6MzMyMjJ9.yDWSO0Ky_OIEAbWTqlHVG1SZtvejdTLdC4dVATz3FQA;\x00g*A\n"
	req, err = ParseHTTPRequest([]byte(requestString))
	assert.Nil(t, nil, err)
	assert.Equal(t, "/_next/static/css/5ecbfdce0834333a.css", req.URL.Path)
	assert.Equal(t, "test.nudgebee.pollux.in", req.Host)
	assert.Equal(t, "GET", req.Method)

	headers = ConvertHeadersToString(req.Header)
	assert.NotNil(t, headers)
}
