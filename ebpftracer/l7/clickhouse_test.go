package l7

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Query packets captured from ClickHouse 24.3 and 26.9, each followed by the
// empty Data packet sent in the same write.
var (
	// ClickHouse 26.9 client and server, negotiated revision 54492
	chLatest = "" +
		"010001000009302e302e302e303a30000000000000000001000c64373537663364353032353111436c69636b486f7573" +
		"6520636c69656e741a09dca90300000d000000000101000000000b6d61785f7468726561647300013200010000020151" +
		"53454c4543542027d0bfd180d0b8d0b2d0b5d18220d0bcd0b8d18027204153206772656574696e672c207b6e3a55496e" +
		"74387d204153206e2c20636f756e7428292046524f4d2073797374656d2e6f6e65016e02032737270002005723ab0cd7" +
		"a3ba8031ffd23ed9bfdfeb901e0000000c00000028b52ffd200c610000010002ffffffff0300000000"
	// ClickHouse 26.9 client (revision 54492) and a 24.3 server: negotiated down to 54467
	chToOlder = "" +
		"010001000009302e302e302e303a30000000000000000001000c64373537663364353032353111436c69636b486f7573" +
		"6520636c69656e741a09dca90300000d000000000b6d61785f74687265616473000132000002015153454c4543542027" +
		"d0bfd180d0b8d0b2d0b5d18220d0bcd0b8d18027204153206772656574696e672c207b6e3a55496e74387d204153206e" +
		"2c20636f756e7428292046524f4d2073797374656d2e6f6e65016e020327372700020090ced47c8d4e82f9aeb0fb84d3" +
		"bc38d2901c0000000a00000028b52ffd200a510000010002ffffffff000000"
	// ClickHouse 24.3 client (revision 54467) and a 26.9 server
	chOlderClient = "" +
		"010001000009302e302e302e303a30000000000000000001000c30396261666639653765373611436c69636b486f7573" +
		"6520636c69656e741803c3a903000012000000000b6d61785f74687265616473000132000002015153454c4543542027" +
		"d0bfd180d0b8d0b2d0b5d18220d0bcd0b8d18027204153206772656574696e672c207b6e3a55496e74387d204153206e" +
		"2c20636f756e7428292046524f4d2073797374656d2e6f6e65016e0203273727000200a783ac6cd55c7a7cb5ac46bddb" +
		"86e21482140000000a000000a0010002ffffffff000000"
	// secondary query from a 26.9 server, initiated by clickhouse-client
	chSecondaryTCP = "" +
		"0100020764656661756c742436393432336663312d353663312d346131382d626530392d336239376666393432663137" +
		"0f3132372e302e302e313a3438333832772a9d30635d060001000c64373537663364353032353111436c69636b486f75" +
		"736520636c69656e741a09dca90300010d0000000001010000000100076469616c656374000a636c69636b686f757365" +
		"11696e7465726163746976655f64656c617900063130303030301171756575655f6d61785f776169745f6d7300013017" +
		"736b69705f756e617661696c61626c655f7368617264730001301c736b69705f756e617661696c61626c655f73686172" +
		"64735f6d6f6465001c756e617661696c61626c655f6f725f7461626c655f6d697373696e671772756e5f71756572795f" +
		"696e5f6261636b67726f756e640001301b616c6c6f775f6578706572696d656e74616c5f616e616c797a657201013128" +
		"656e61626c655f7061636b65645f737472696e675f6b6579735f696e5f6167677265676174696f6e0001310001000002" +
		"016353454c45435420277365636f6e6461727920746370272041532060277365636f6e646172792074637027602c2063" +
		"6f756e7428292041532060636f756e742829602046524f4d206073797374656d602e606f6e656020415320605f5f7461" +
		"626c65316000070c5f73686172645f636f756e746600d323159ba3d0a17d297a2780d77590370000002500000028b52f" +
		"fd2025290100010002ffffffff03000001010c5f73686172645f636f756e740655496e7433320001000000070a5f7368" +
		"6172645f6e756dc80abdf64a95333be5bbf296724a52d290350000002300000028b52ffd2023190100010002ffffffff" +
		"03000001010a5f73686172645f6e756d0655496e7433320001000000"
	// secondary query from a 26.9 server, initiated over HTTP
	chSecondaryHTTP = "" +
		"0100020764656661756c742436623033363932352d343964302d343734352d383866352d623234656430396533663662" +
		"0f3139322e302e322e343a3532353136d23ec133635d060002020b6375726c2f382e32322e30000000012f0001000000" +
		"0000000000000100076469616c656374000a636c69636b686f75736511696e7465726163746976655f64656c61790006" +
		"3130303030301171756575655f6d61785f776169745f6d7300013017736b69705f756e617661696c61626c655f736861" +
		"7264730001301c736b69705f756e617661696c61626c655f7368617264735f6d6f6465001c756e617661696c61626c65" +
		"5f6f725f7461626c655f6d697373696e671772756e5f71756572795f696e5f6261636b67726f756e640001301b616c6c" +
		"6f775f6578706572696d656e74616c5f616e616c797a657201013128656e61626c655f7061636b65645f737472696e67" +
		"5f6b6579735f696e5f6167677265676174696f6e0001310001000002016553454c45435420277365636f6e6461727920" +
		"68747470272041532060277365636f6e64617279206874747027602c20636f756e7428292041532060636f756e742829" +
		"602046524f4d206073797374656d602e606f6e656020415320605f5f7461626c65316000070c5f73686172645f636f75" +
		"6e746600d323159ba3d0a17d297a2780d77590370000002500000028b52ffd2025290100010002ffffffff0300000101" +
		"0c5f73686172645f636f756e740655496e7433320001000000"
)

func chPacket(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	require.NoError(t, err)
	return b
}

func TestParseClickHouseRevisions(t *testing.T) {
	const query = "SELECT 'привет мир' AS greeting, {n:UInt8} AS n, count() FROM system.one"
	for name, tc := range map[string]struct{ packet, query string }{
		"latest":          {chLatest, query},
		"older server":    {chToOlder, query},
		"older client":    {chOlderClient, query},
		"secondary, TCP":  {chSecondaryTCP, "SELECT 'secondary tcp' AS `'secondary tcp'`, count() AS `count()` FROM `system`.`one` AS `__table1`"},
		"secondary, HTTP": {chSecondaryHTTP, "SELECT 'secondary http' AS `'secondary http'`, count() AS `count()` FROM `system`.`one` AS `__table1`"},
	} {
		got, ok := ParseClickhouse(chPacket(t, tc.packet))
		assert.True(t, ok, name)
		assert.Equal(t, tc.query, got, name)
	}
}

func TestParseClickHouseTruncatedMultiByte(t *testing.T) {
	p := chPacket(t, chLatest)
	i := bytes.Index(p, []byte("привет"))
	require.Greater(t, i, 0)
	// the capture ends inside "р", the second character
	got, ok := ParseClickhouse(p[:i+3])
	assert.True(t, ok)
	assert.Equal(t, "SELECT 'п...<TRUNCATED>", got)
}

func TestParseClickHouseUnreadableLayout(t *testing.T) {
	// A Query packet that fits no known layout is still ClickHouse, just without a query.
	p := chPacket(t, chLatest)
	i := bytes.Index(p, []byte("max_threads"))
	require.Greater(t, i, 0)
	p[i] = '-'
	got, ok := ParseClickhouse(p)
	assert.True(t, ok)
	assert.Equal(t, "", got)

	// An unknown interface isn't a Query packet.
	p = chPacket(t, chLatest)
	i = bytes.Index(p, []byte("0.0.0.0:0")) + len("0.0.0.0:0") + 8
	p[i] = 12
	_, ok = ParseClickhouse(p)
	assert.False(t, ok)
}

// Reading a packet with the wrong layout must not produce made-up query text:
// corrupt each byte before the query and check the result is the real query,
// a prefix of it, or nothing.
func TestParseClickHouseCorruptedHeader(t *testing.T) {
	for _, h := range []string{chLatest, chToOlder, chOlderClient, chSecondaryTCP, chSecondaryHTTP} {
		p := chPacket(t, h)
		want, ok := ParseClickhouse(p)
		require.True(t, ok)
		end := bytes.Index(p, []byte(want[:6]))
		require.Greater(t, end, 0)
		for i := 1; i < end; i++ {
			for _, v := range []byte{0, 1, 2, 0x7f, 0x80, 0xff, p[i] + 1, p[i] - 1} {
				c := bytes.Clone(p)
				c[i] = v
				got, _ := ParseClickhouse(c)
				got, _ = strings.CutSuffix(got, "...<TRUNCATED>")
				if !strings.HasPrefix(want, got) {
					t.Errorf("byte %d set to %#x: got %q", i, v, got)
				}
			}
		}
	}
}
