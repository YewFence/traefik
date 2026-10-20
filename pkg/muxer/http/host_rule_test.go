package http

import "testing"

func TestRuleMatchesHost(t *testing.T) {
	tests := []struct {
		name    string
		rule    string
		syntax  string
		host    string
		matches bool
	}{
		{name: "host regexp matches", rule: "HostRegexp(`^[a-z]+\\.example\\.com$`)", host: "api.example.com", matches: true},
		{name: "host regexp does not match", rule: "HostRegexp(`^[a-z]+\\.example\\.com$`)", host: "example.net", matches: false},
		{name: "host regexp with path condition", rule: "HostRegexp(`^api\\.example\\.com$`) && PathPrefix(`/api`)", host: "api.example.com", matches: true},
		{name: "negated host", rule: "!Host(`blocked.example.com`)", host: "api.example.com", matches: true},
		{name: "v2 host regexp", rule: "HostRegexp(`{subdomain:[a-z]+}.example.com`)", syntax: "v2", host: "api.example.com", matches: true},
		{name: "wildcard certificate intersects host regexp", rule: "HostRegexp(`^api\\.example\\.com$`)", host: "*.example.com", matches: true},
		{name: "wildcard certificate disjoint from regexp", rule: "HostRegexp(`^api\\.example\\.net$`)", host: "*.example.com", matches: false},
		{name: "wildcard intersects both regexp branches", rule: "HostRegexp(`^a.*\\.example\\.com$`) && HostRegexp(`^.*z\\.example\\.com$`)", host: "*.example.com", matches: true},
		{name: "wildcard cannot satisfy conflicting branches", rule: "HostRegexp(`^a\\.example\\.com$`) && HostRegexp(`^b\\.example\\.com$`)", host: "*.example.com", matches: false},
		{name: "wildcard excluded by negated regexp", rule: "!HostRegexp(`^[^.]+\\.example\\.com$`)", host: "*.example.com", matches: false},
		{name: "wildcard survives single excluded hostname", rule: "!Host(`api.example.com`)", host: "*.example.com", matches: true},
		{name: "wildcard does not cover nested subdomain", rule: "HostRegexp(`^api\\.nested\\.example\\.com$`)", host: "*.example.com", matches: false},
		{name: "unanchored regexp", rule: "HostRegexp(`api`)", host: "*.example.com", matches: true},
		{name: "negated request attributes stay unconstrained", rule: "HostRegexp(`^api\\.example\\.com$`) && !PathPrefix(`/private`)", host: "*.example.com", matches: true},
		{name: "wildcard rejects overlong label", rule: "HostRegexp(`^a{64}\\.example\\.com$`)", host: "*.example.com", matches: false},
		{name: "wildcard accepts maximum label length", rule: "HostRegexp(`^a{63}\\.example\\.com$`)", host: "*.example.com", matches: true},
		{name: "wildcard honors word boundaries", rule: "HostRegexp(`\\bapi\\b`)", host: "*.example.com", matches: true},
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
