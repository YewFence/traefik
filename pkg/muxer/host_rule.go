package muxer

import (
	"encoding/binary"
	"errors"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"

	"github.com/traefik/traefik/v3/pkg/rules"
)

// HostRuleIntersects reports whether a certificate covers a hostname allowed by a rule.
// Patterns returns regular expressions for host leaves and nil for other matchers.
// Request attributes other than the hostname remain unconstrained, including when negated.
func HostRuleIntersects(tree *rules.Tree, certificateDomain string, patterns func(*rules.Tree) ([]string, error)) (bool, error) {
	var expressions []*regexp.Regexp
	leaves := make(map[*rules.Tree][]int)
	var compileTree func(*rules.Tree) error
	compileTree = func(node *rules.Tree) error {
		if node.Matcher == "and" || node.Matcher == "or" {
			if err := compileTree(node.RuleLeft); err != nil {
				return err
			}
			return compileTree(node.RuleRight)
		}
		values, err := patterns(node)
		if err != nil {
			return err
		}
		if values == nil {
			return nil
		}
		leaves[node] = []int{}
		for _, value := range values {
			re, err := regexp.Compile(value)
			if err != nil {
				return err
			}
			leaves[node] = append(leaves[node], len(expressions))
			expressions = append(expressions, re)
		}
		return nil
	}
	if err := compileTree(tree); err != nil {
		return false, err
	}

	var evaluate func(*rules.Tree, []bool) bool
	evaluate = func(node *rules.Tree, matches []bool) bool {
		switch node.Matcher {
		case "and":
			return evaluate(node.RuleLeft, matches) && evaluate(node.RuleRight, matches)
		case "or":
			return evaluate(node.RuleLeft, matches) || evaluate(node.RuleRight, matches)
		}
		indices, known := leaves[node]
		if !known {
			return true
		}
		matched := false
		for _, index := range indices {
			matched = matched || matches[index]
		}
		return matched != node.Not
	}

	certificateDomain = strings.ToLower(strings.TrimSuffix(certificateDomain, "."))
	if !strings.HasPrefix(certificateDomain, "*.") {
		matches := make([]bool, len(expressions))
		for index, expression := range expressions {
			matches[index] = expression.MatchString(certificateDomain)
		}
		return evaluate(tree, matches), nil
	}

	// DNS labels are bounded, so this product search only visits valid wildcard hostnames.
	label := `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`
	certificatePattern := `\A` + label + regexp.QuoteMeta(certificateDomain[1:]) + `\z`
	programs := make([]*syntax.Prog, 0, len(expressions)+1)
	patternsToCompile := []string{certificatePattern}
	for _, expression := range expressions {
		patternsToCompile = append(patternsToCompile, `(?s:.*)(?:`+expression.String()+`)(?s:.*)`)
	}
	for _, pattern := range patternsToCompile {
		parsed, err := syntax.Parse(pattern, syntax.Perl)
		if err != nil {
			return false, err
		}
		program, err := syntax.Compile(parsed.Simplify())
		if err != nil {
			return false, err
		}
		programs = append(programs, program)
	}

	type state struct {
		positions [][]uint32
		previous  rune
		length    int
	}
	initial := state{positions: make([][]uint32, len(programs)), previous: -1}
	for index, program := range programs {
		initial.positions[index] = []uint32{uint32(program.Start)}
	}
	queue := []state{initial}
	visited := map[string]struct{}{hostStateKey(initial.positions, initial.previous): {}}
	alphabet := "abcdefghijklmnopqrstuvwxyz0123456789-."
	for head := 0; head < len(queue); head++ {
		current := queue[head]
		matches := make([]bool, len(programs))
		for index, program := range programs {
			for _, position := range hostClosure(program, current.positions[index], current.previous, -1) {
				if program.Inst[position].Op == syntax.InstMatch {
					matches[index] = true
					break
				}
			}
		}
		if matches[0] && evaluate(tree, matches[1:]) {
			return true, nil
		}
		if current.length == 253 {
			continue
		}

		for _, character := range alphabet {
			next := state{positions: make([][]uint32, len(programs)), previous: character, length: current.length + 1}
			for index, program := range programs {
				for _, position := range hostClosure(program, current.positions[index], current.previous, character) {
					instruction := &program.Inst[position]
					switch instruction.Op {
					case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
						if instruction.MatchRune(character) {
							next.positions[index] = append(next.positions[index], instruction.Out)
						}
					}
				}
				slices.Sort(next.positions[index])
				next.positions[index] = slices.Compact(next.positions[index])
			}
			if len(next.positions[0]) == 0 {
				continue
			}
			key := hostStateKey(next.positions, next.previous)
			if _, seen := visited[key]; seen {
				continue
			}
			if len(visited) >= 10000 {
				return false, errors.New("hostname intersection exceeds 10000 states")
			}
			visited[key] = struct{}{}
			queue = append(queue, next)
		}
	}
	return false, nil
}

func hostClosure(program *syntax.Prog, positions []uint32, previous, next rune) []uint32 {
	pending := slices.Clone(positions)
	seen := make([]bool, len(program.Inst))
	var result []uint32
	context := syntax.EmptyOpContext(previous, next)
	for len(pending) > 0 {
		position := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen[position] {
			continue
		}
		seen[position] = true
		instruction := &program.Inst[position]
		switch instruction.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			pending = append(pending, instruction.Out, instruction.Arg)
		case syntax.InstCapture, syntax.InstNop:
			pending = append(pending, instruction.Out)
		case syntax.InstEmptyWidth:
			if syntax.EmptyOp(instruction.Arg)&context == syntax.EmptyOp(instruction.Arg) {
				pending = append(pending, instruction.Out)
			}
		case syntax.InstFail:
		default:
			result = append(result, position)
		}
	}
	return result
}

func hostStateKey(positions [][]uint32, previous rune) string {
	var key []byte
	boundary := byte(0)
	if previous == -1 {
		boundary = 1
	} else if syntax.IsWordChar(previous) {
		boundary = 2
	}
	key = append(key, boundary)
	for _, group := range positions {
		key = binary.LittleEndian.AppendUint32(key, uint32(len(group)))
		for _, position := range group {
			key = binary.LittleEndian.AppendUint32(key, position)
		}
	}
	return string(key)
}

// HostExpressionPattern converts a Host or HostSNI expression into an anchored pattern.
func HostExpressionPattern(expression string) string {
	expression = strings.ToLower(strings.TrimSuffix(expression, "."))
	switch {
	case expression == "*":
		return `.*`
	case strings.HasPrefix(expression, "**."):
		return `\A.+\.` + regexp.QuoteMeta(expression[3:]) + `\z`
	case strings.HasPrefix(expression, "*."):
		return `\A[^.]+\.` + regexp.QuoteMeta(expression[2:]) + `\z`
	default:
		return `\A` + regexp.QuoteMeta(expression) + `\z`
	}
}
