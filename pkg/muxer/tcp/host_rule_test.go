package tcp

import "testing"

func TestRuleMatchesHost(t *testing.T) {
	tests := []struct {
		name    string
		rule    string
		syntax  string
		host    string
		matches bool
	}{
		{name: "host sni regexp matches", rule: "HostSNIRegexp(`^[a-z]+\\.example\\.com$`)", host: "api.example.com", matches: true},
		{name: "host sni regexp does not match", rule: "HostSNIRegexp(`^[a-z]+\\.example\\.com$`)", host: "example.net", matches: false},
		{name: "host sni with alpn", rule: "HostSNI(`api.example.com`) && ALPN(`h2`)", host: "api.example.com", matches: true},
		{name: "v2 host sni", rule: "HostSNI(`api.example.com`)", syntax: "v2", host: "api.example.com", matches: true},
		{name: "wildcard certificate intersects host sni regexp", rule: "HostSNIRegexp(`^api\\.example\\.com$`)", host: "*.example.com", matches: true},
		{name: "wildcard certificate disjoint from regexp", rule: "HostSNIRegexp(`^api\\.example\\.net$`)", host: "*.example.com", matches: false},
		{name: "v2 wildcard regexp intersection", rule: "HostSNIRegexp(`{subdomain:api}.example.com`)", syntax: "v2", host: "*.example.com", matches: true},
		{name: "wildcard cannot satisfy conflicting branches", rule: "HostSNI(`api.example.com`) && !HostSNI(`api.example.com`)", host: "*.example.com", matches: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches, err := RuleMatchesHost(test.rule, test.syntax, test.host)
			if err != nil {
				t.Fatal(err)
			}
			if matches != test.matches {
				t.Fatalf("expected match=%t, got %t", test.matches, matches)
			}
		})
	}
}
