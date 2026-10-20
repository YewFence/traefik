package tcp

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/go-acme/lego/v5/challenge/tlsalpn01"
	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/ip"
	"github.com/traefik/traefik/v3/pkg/muxer"
)

var tcpFuncsV2 = map[string]func(*matchersTree, ...string) error{
	"ALPN":          alpnV2,
	"ClientIP":      clientIPV2,
	"HostSNI":       hostSNIV2,
	"HostSNIRegexp": hostSNIRegexpV2,
}

var hostOrIPv2 = regexp.MustCompile(`^[[:word:]\.\-\:]+$`)

func clientIPV2(tree *matchersTree, clientIPs ...string) error {
	checker, err := ip.NewChecker(clientIPs)
	if err != nil {
		return fmt.Errorf("could not initialize IP Checker for \"ClientIP\" matcher: %w", err)
	}

	tree.matcher = func(meta ConnData) bool {
		if meta.remoteIP == "" {
			return false
		}

		ok, err := checker.Contains(meta.remoteIP)
		if err != nil {
			log.Warn().Err(err).Msg("ClientIP matcher: could not match remote address")
			return false
		}
		return ok
	}

	return nil
}

// alpnV2 checks if any of the connection ALPN protocols matches one of the matcher protocols.
func alpnV2(tree *matchersTree, protos ...string) error {
	if len(protos) == 0 {
		return errors.New("empty value for \"ALPN\" matcher is not allowed")
	}

	for _, proto := range protos {
		if proto == tlsalpn01.ACMETLS1Protocol {
			return fmt.Errorf("invalid protocol value for \"ALPN\" matcher, %q is not allowed", proto)
		}
	}

	tree.matcher = func(meta ConnData) bool {
		for _, proto := range meta.alpnProtos {
			if slices.Contains(protos, proto) {
				return true
			}
		}

		return false
	}

	return nil
}

// hostSNIV2 checks if the SNI Host of the connection match the matcher host.
func hostSNIV2(tree *matchersTree, hosts ...string) error {
	if len(hosts) == 0 {
		return errors.New("empty value for \"HostSNI\" matcher is not allowed")
	}

	for i, host := range hosts {
		// Special case to allow global wildcard
		if host == "*" {
			continue
		}

		if !hostOrIPv2.MatchString(host) {
			return fmt.Errorf("invalid value for \"HostSNI\" matcher, %q is not a valid hostname or IP", host)
		}

		hosts[i] = strings.ToLower(host)
	}

	tree.matcher = func(meta ConnData) bool {
		// Since a HostSNI(`*`) rule has been provided as catchAll for non-TLS TCP,
		// it allows matching with an empty serverName.
		// Which is why we make sure to take that case into account before
		// checking meta.serverName.
		if hosts[0] == "*" {
			return true
		}

		if meta.serverName == "" {
			return false
		}

		for _, host := range hosts {
			if host == "*" {
				return true
			}

			if host == meta.serverName {
				return true
			}

			// trim trailing period in case of FQDN
			host = strings.TrimSuffix(host, ".")
			if host == meta.serverName {
				return true
			}
		}

		return false
	}

	return nil
}

// hostSNIRegexpV2 checks if the SNI Host of the connection matches the matcher host regexp.
func hostSNIRegexpV2(tree *matchersTree, templates ...string) error {
	if len(templates) == 0 {
		return errors.New("empty value for \"HostSNIRegexp\" matcher is not allowed")
	}

	var regexps []*regexp.Regexp

	for _, template := range templates {
		preparedPattern, err := muxer.HostTemplatePattern(template, true)
		if err != nil {
			return fmt.Errorf("invalid pattern value for \"HostSNIRegexp\" matcher, %q is not a valid pattern: %w", template, err)
		}

		regexp, err := regexp.Compile(preparedPattern)
		if err != nil {
			return err
		}

		regexps = append(regexps, regexp)
	}

	tree.matcher = func(meta ConnData) bool {
		for _, regexp := range regexps {
			if regexp.MatchString(meta.serverName) {
				return true
			}
		}

		return false
	}

	return nil
}
