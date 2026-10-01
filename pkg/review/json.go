package review

import (
	"errors"
	"unicode/utf16"
	"unicode/utf8"
)

// ---------------------------------------------------------------- encoder

// appendJSONString appends s as a JSON string with the minimal escaping
// fixed by the protocol: \" \\ \n \r \t, \u00xx (lowercase hex) for the
// other bytes below 0x20, everything else verbatim (in particular '<', '>',
// '&', DEL, U+2028 and U+2029 are NOT escaped). The caller guarantees that
// s is valid UTF-8.
//
// A hand-written encoder is used instead of encoding/json because the
// output is hashed and compared byte for byte across nodes and releases:
// encoding/json's escaping rules (HTML escaping, U+2028, replacement of
// invalid UTF-8) are an implementation detail that has changed between Go
// versions and may change again.
func appendJSONString(dst []byte, s string) []byte {
	const hexdigits = "0123456789abcdef"
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		dst = append(dst, s[start:i]...)
		start = i + 1
		switch c {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			dst = append(dst, '\\', 'u', '0', '0', hexdigits[c>>4], hexdigits[c&15])
		}
	}
	dst = append(dst, s[start:]...)
	return append(dst, '"')
}

// ----------------------------------------------------------------- parser

// A strict JSON reader for provider responses. encoding/json is not used
// for consensus-relevant parsing because it is lenient in ways that create
// ambiguity: it accepts duplicate object keys (last one wins), matches
// struct field names case-insensitively, and silently replaces invalid
// UTF-8. Two implementations (or two Go releases) that resolve such input
// differently would disagree about a verdict.

const (
	jsonMaxDepth = 32
)

type jkind uint8

const (
	jNull jkind = iota
	jBool
	jNumber
	jString
	jArray
	jObject
)

type jmember struct {
	key string
	val *jvalue
}

type jvalue struct {
	kind jkind
	b    bool
	str  string // string value, or the raw text of a number
	arr  []*jvalue
	obj  []jmember // in document order; keys are unique
}

// get returns the member named key, or nil.
func (v *jvalue) get(key string) *jvalue {
	if v == nil || v.kind != jObject {
		return nil
	}
	for i := range v.obj {
		if v.obj[i].key == key {
			return v.obj[i].val
		}
	}
	return nil
}

// getString returns the string member named key.
func (v *jvalue) getString(key string) (string, bool) {
	m := v.get(key)
	if m == nil || m.kind != jString {
		return "", false
	}
	return m.str, true
}

type jparser struct {
	data []byte
	pos  int
}

func parseJSON(data []byte) (*jvalue, error) {
	p := &jparser{data: data}
	p.ws()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.pos != len(p.data) {
		return nil, errors.New("json: trailing data")
	}
	return v, nil
}

func (p *jparser) ws() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *jparser) lit(s string) bool {
	if len(p.data)-p.pos >= len(s) && string(p.data[p.pos:p.pos+len(s)]) == s {
		p.pos += len(s)
		return true
	}
	return false
}

func (p *jparser) value(depth int) (*jvalue, error) {
	if depth > jsonMaxDepth {
		return nil, errors.New("json: nesting too deep")
	}
	if p.pos >= len(p.data) {
		return nil, errors.New("json: unexpected end")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		return &jvalue{kind: jString, str: s}, nil
	case c == 't':
		if p.lit("true") {
			return &jvalue{kind: jBool, b: true}, nil
		}
	case c == 'f':
		if p.lit("false") {
			return &jvalue{kind: jBool}, nil
		}
	case c == 'n':
		if p.lit("null") {
			return &jvalue{kind: jNull}, nil
		}
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	return nil, errors.New("json: unexpected character")
}

func (p *jparser) object(depth int) (*jvalue, error) {
	p.pos++ // {
	v := &jvalue{kind: jObject}
	p.ws()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return v, nil
	}
	for {
		p.ws()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, errors.New("json: expected object key")
		}
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		// Linear scan: objects in provider responses have a handful
		// of members, and the input size is capped, so this cannot
		// be exploited for quadratic blow-up beyond that cap.
		for i := range v.obj {
			if v.obj[i].key == key {
				return nil, errors.New("json: duplicate object key")
			}
		}
		p.ws()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, errors.New("json: expected ':'")
		}
		p.pos++
		p.ws()
		val, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		v.obj = append(v.obj, jmember{key, val})
		p.ws()
		if p.pos >= len(p.data) {
			return nil, errors.New("json: unexpected end in object")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return v, nil
		default:
			return nil, errors.New("json: expected ',' or '}'")
		}
	}
}

func (p *jparser) array(depth int) (*jvalue, error) {
	p.pos++ // [
	v := &jvalue{kind: jArray}
	p.ws()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return v, nil
	}
	for {
		p.ws()
		val, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		v.arr = append(v.arr, val)
		p.ws()
		if p.pos >= len(p.data) {
			return nil, errors.New("json: unexpected end in array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return v, nil
		default:
			return nil, errors.New("json: expected ',' or ']'")
		}
	}
}

func (p *jparser) number() (*jvalue, error) {
	start := p.pos
	digits := func() int {
		n := 0
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
			n++
		}
		return n
	}
	if p.data[p.pos] == '-' {
		p.pos++
	}
	if p.pos < len(p.data) && p.data[p.pos] == '0' {
		p.pos++
	} else if digits() == 0 {
		return nil, errors.New("json: bad number")
	}
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		p.pos++
		if digits() == 0 {
			return nil, errors.New("json: bad number")
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if digits() == 0 {
			return nil, errors.New("json: bad number")
		}
	}
	return &jvalue{kind: jNumber, str: string(p.data[start:p.pos])}, nil
}

func (p *jparser) hex4() (rune, bool) {
	if len(p.data)-p.pos < 4 {
		return 0, false
	}
	var r rune
	for i := 0; i < 4; i++ {
		c := p.data[p.pos+i]
		switch {
		case c >= '0' && c <= '9':
			r = r<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	p.pos += 4
	return r, true
}

// str parses a string. Rejected: raw control characters, invalid UTF-8,
// unknown escapes, and unpaired UTF-16 surrogates in \u escapes.
func (p *jparser) str() (string, error) {
	p.pos++ // opening quote
	var out []byte
	start := p.pos
	for {
		if p.pos >= len(p.data) {
			return "", errors.New("json: unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			out = append(out, p.data[start:p.pos]...)
			p.pos++
			return string(out), nil
		case c < 0x20:
			return "", errors.New("json: control character in string")
		case c == '\\':
			out = append(out, p.data[start:p.pos]...)
			p.pos++
			if p.pos >= len(p.data) {
				return "", errors.New("json: unterminated escape")
			}
			e := p.data[p.pos]
			p.pos++
			switch e {
			case '"', '\\', '/':
				out = append(out, e)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, ok := p.hex4()
				if !ok {
					return "", errors.New("json: bad \\u escape")
				}
				if utf16.IsSurrogate(r) {
					if !p.lit("\\u") {
						return "", errors.New("json: unpaired surrogate")
					}
					r2, ok := p.hex4()
					if !ok {
						return "", errors.New("json: bad \\u escape")
					}
					r = utf16.DecodeRune(r, r2)
					if r == utf8.RuneError {
						return "", errors.New("json: unpaired surrogate")
					}
				}
				out = utf8.AppendRune(out, r)
			default:
				return "", errors.New("json: unknown escape")
			}
			start = p.pos
		case c < utf8.RuneSelf:
			p.pos++
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size == 1 {
				return "", errors.New("json: invalid UTF-8")
			}
			p.pos += size
		}
	}
}
