package muxer

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

// HostTemplatePattern converts a v2 HostRegexp template into an anchored pattern.
// It uses the same brace expansion as the routing muxer's host templates.
func HostTemplatePattern(template string, caseInsensitive bool) (string, error) {
	indices, err := braceIndices(template)
	if err != nil {
		return "", err
	}

	pattern := bytes.NewBufferString("")
	if caseInsensitive {
		pattern.WriteString("(?i)")
	}
	pattern.WriteByte('^')
	var end int
	for index := 0; index < len(indices); index += 2 {
		raw := template[end:indices[index]]
		end = indices[index+1]
		parts := strings.SplitN(template[indices[index]+1:end-1], ":", 2)
		name := parts[0]
		value := "[^.]+"
		if len(parts) == 2 {
			value = parts[1]
		}
		if name == "" || value == "" {
			return "", fmt.Errorf("mux: missing name or pattern in %q", template[indices[index]:end])
		}
		_, _ = fmt.Fprintf(pattern, "%s(?P<v%d>%s)", regexp.QuoteMeta(raw), index/2, value)
	}
	pattern.WriteString(regexp.QuoteMeta(template[end:]))
	pattern.WriteByte('$')
	return pattern.String(), nil
}

func braceIndices(value string) ([]int, error) {
	var level, start int
	var indices []int
	for index := range len(value) {
		switch value[index] {
		case '{':
			level++
			if level == 1 {
				start = index
			}
		case '}':
			level--
			if level == 0 {
				indices = append(indices, start, index+1)
			} else if level < 0 {
				return nil, fmt.Errorf("mux: unbalanced braces in %q", value)
			}
		}
	}
	if level != 0 {
		return nil, fmt.Errorf("mux: unbalanced braces in %q", value)
	}
	return indices, nil
}
