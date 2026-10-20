package parse

import "testing"

func TestParseDNSGolden(t *testing.T) {
	dir := "testdata/dns"
	cases := []string{
		"01_c2_beacon",
		"02_benign",
		"03_malformed",
	}
	for _, name := range cases {
		name := name
		t.Run(name, func(t *testing.T) {
			runGoldenCase(t, dir, name, func(line string) (*ParsedEvent, error) {
				return ParseDNS(line, "lab-host-1", fixedReceivedAt)
			})
		})
	}
}
