package http

import (
	"errors"
	"strings"

	"github.com/traefik/traefik/v3/pkg/muxer"
	"github.com/traefik/traefik/v3/pkg/rules"
)

// RuleMatchesHost reports whether a router rule intersects a certificate's hostnames.
func RuleMatchesHost(rule, syntax, host string) (bool, error) {
	funcs := httpFuncs
	if strings.EqualFold(syntax, "v2") {
		funcs = httpFuncsV2
	}
	var matchers []string
	for matcher := range funcs {
		matchers = append(matchers, matcher)
	}
	parser, err := rules.NewParser(matchers)
	if err != nil {
		return false, err
	}
	parsed, err := parser.Parse(rule)
	if err != nil {
		return false, err
	}
	builder, ok := parsed.(rules.TreeBuilder)
	if !ok {
		return false, errors.New("unable to build router rule tree")
	}

	return muxer.HostRuleIntersects(builder(), host, func(node *rules.Tree) ([]string, error) {
		var patterns []string
		switch strings.ToLower(node.Matcher) {
		case "host":
			for _, value := range node.Value {
				patterns = append(patterns, muxer.HostExpressionPattern(value))
			}
		case "hostregexp":
			for _, value := range node.Value {
				if strings.EqualFold(syntax, "v2") {
					pattern, err := muxer.HostTemplatePattern(value, false)
					if err != nil {
						return nil, err
					}
					patterns = append(patterns, pattern)
				} else {
					patterns = append(patterns, value)
				}
			}
		default:
			return nil, nil
		}
		if err := rules.CheckRule(node); err != nil {
			return nil, err
		}
		return patterns, nil
	})
}
