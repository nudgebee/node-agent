package l7

import (
	"bytes"
	"encoding/binary"
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
	// requestString := "GET /latest/meta-data/public-hostname HTTP/1.1\r\nHost: 169.254.169.254\r\nUser-Agent: aws-sdk-go/1.44.216 (go1.20.10; linux; amd64)\r\nX-Aws-Ec2-Metadata-Token: AQAEAFUlJzNnMsa7JA5u9mJyJIgGQwSudnYZkp6-LjKeRNagn8umUQ==\r\nAccept-Encoding: gzip\r\n\r\n"
	// req, err := ParseHTTPRequest([]byte(requestString))
	// assert.Nil(t, nil, err)
	// assert.Equal(t, "/latest/meta-data/public-hostname", req.URL.Path)
	// assert.Equal(t, "169.254.169.254", req.Host)
	// assert.Equal(t, "GET", req.Method)

	// headers := ConvertHeadersToString(req.Header)
	// assert.NotNil(t, headers)

	// requestString = "POST /v1.0/teams/f73ccda2-234d-44ab-83bc-90f430e6f4eb/channels/19:zoWRYmvdg7sQmYpDpjuJ2TB72es7FOcFj32-Vvn_HRk1@thread.tacv2/messages HTTP/1.1\r\nHost: graph.microsoft.com\r\nUser-Agent: python-requests/2.31.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nAuthorization: Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6IlREN3V2cVJONU51R2ZFR3ZzNGN0anJCaFZqTHBkUjBNT0NMS3FTV3ZRNjQiLCJhbGciOiJSUzI1NiIsIng1dCI6InEtMjNmYWxldlpoaEQzaG05Q1Fia1A1TVF5VSIsImtpZCI6InEtMjNmYWxldlpoaEQzaG05Q1Fia1A1TVF5VSJ9.eyJhdWQiOiIwMDAwMDAwMy0wMDAwLTAwMDAtYzAwMC0wMDAwMDAwMDAwMDAiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9hM2YyNDYyNi1hMjQyLTRjYzctYjNmZS00ZTJlNzZlODA1YjYvIiwiaWF0IjoxNzEyMzMyODk3LCJuYmYiOjE3MTIzMzI4OTcsImV4cCI6MTcxMjMzODE2OSwiYWNjdCI6MCwiYWNyIjoiMSIsImFpbyI6IkFWUUFxLzhXQUFBQXorOThMV0t0aktOWGN4NW9CYkJmVWFDa0gzK3ZRV1RVMTV3aDRoSTdDK09iVU5KYlp6YW4xY3I4YmN2WVFqL0FoOUkvcUZxR0VTZERQcjVjSDRUVVlkUjB5NHZZdTU2YUxxYnZsanZDSFBzPSIsImFtciI6WyJwd2QiLCJtZmEiXSwiYXBwX2Rpc3BsYXluYW1lIjoiTnVkZ2ViZWUiLCJhcHBpZCI6ImE0ZjQ0MTM5LTFhNTktNDg0N\x00"
	// req, err = ParseHTTPRequest([]byte(requestString))
	// assert.Nil(t, nil, err)
	// assert.Equal(t, "/v1.0/teams/f73ccda2-234d-44ab-83bc-90f430e6f4eb/channels/19:zoWRYmvdg7sQmYpDpjuJ2TB72es7FOcFj32-Vvn_HRk1@thread.tacv2/messages", req.URL.Path)
	// assert.Equal(t, "POST", req.Method)
	// headers = ConvertHeadersToString(req.Header)
	// assert.NotNil(t, headers)

	// requestString = "GET /api/v1/services?labelSelector=app%3Dkube-prometheus-stack-prometheus HTTP/1.1\r\nHost: 10.100.0.1\r\nAccept-Encoding: identity\r\nAccept: application/json\r\nUser-Agent: OpenAPI-Generator/26.1.0/python\r\nauthorization: bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjNhZTFlNjlkN2I1ZmFkNzhhNTg2YTVjN2JmMDNjOGU3YjUzNGI4N2MifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjIl0sImV4cCI6MTc0Mzg2NzUwOCwiaWF0IjoxNzEyMzMxNTA4LCJpc3MiOiJodHRwczovL29pZGMuZWtzLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tL2lkL0I4RkU4OUQ4MjdEN0Q2RTE0REIyMUMzRkIwQTk1Q0E3Iiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJwcm9kZW52NTQiLCJwb2QiOnsibmFtZSI6InByb2RlbnY1NC1ydW5uZXItNmJiNzc4YjljOC1tcG5oZiIsInVpZCI6ImRkMjAzOTYxLWYwZWMtNGE5Yy1hZjVlLTk4NDY1Y2JmZTBjYiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoicHJvZGVudjU0LXJ1bm5lci1zZXJ2aWNlLWFjY291bnQiLCJ1aWQiOiJmNjhhNWM5NC1kZjFmLTQ4M2YtOTM1ZC0wNjZiZTUyOThjNTcifSwid2FybmFmdGVyIjoxNzEyMzM1MTE1fSwibmJmIjoxNzEyMzMxNTA4LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6cHJvZGVudjU0OnByb2RlbnY1NC1ydW5uZXItc2VydmljZS1hY2NvdW50In0.lDx2mQxgICBk3GXK7aR9Yr\x00"
	// req, err = ParseHTTPRequest([]byte(requestString))
	// assert.Nil(t, nil, err)
	// assert.Equal(t, "GET", req.Method)
	// assert.Equal(t, "10.100.0.1", req.Host)
	// headers = ConvertHeadersToString(req.Header)
	// assert.NotNil(t, headers)

	requestString := "POST /api/v1/query?query=%28%0A++%28%0A++++%23+too+slow%0A++++sum+by+%28cluster%29+%28rate%28apiserver_request_sli_duration_seconds_count%7Bjob%3D%22apiserver%22%2Cverb%3D~%22LIST%7CGET%22%2Csubresource%21~%22proxy%7Cattach%7Clog%7Cexec%7Cportforward%22%7D%5B1d%5D%29%29%0A++++-%0A++++%28%0A++++++%28%0A++++++++sum+by+%28cluster%29+%28rate%28apiserver_request_sli_duration_seconds_bucket%7Bjob%3D%22apiserver%22%2Cverb%3D~%22LIST%7CGET%22%2Csubresource%21~%22proxy%7Cattach%7Clog%7Cexec%7Cportforward%22%2Cscope%3D~%22resource%7C%22%2Cle%3D%221%22%7D%5B1d%5D%29%29%0A++++++++or%0A++++++++vector%280%29%0A++++++%29%0A++++++%2B%0A++++++sum+by+%28cluster%29+%28rate%28apiserver_request_sli_duration_seconds_bucket%7Bjob%3D%22apiserver%22%2Cverb%3D~%22LIST%7CGET%22%2Csubresource%21~%22proxy%7Cattach%7Clog%7Cexec%7Cportforward%22%2Cscope%3D%22namespace%22%2Cle%3D%225%22%7D%5B1d%5D%29%29%0A++++++%2B%0A++++++sum+by+%28cluster%29+%28rate%28apiserver_request_sli_duration_seconds_bucket%7Bjob%3D%22apiserver%22%2Cverb%3D~%22LIST\x00"
	req, err := ParseHTTPRequest([]byte(requestString))
	assert.Nil(t, nil, err)
	assert.Equal(t, "POST", req.Method)
}
