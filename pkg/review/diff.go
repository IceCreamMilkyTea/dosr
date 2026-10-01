package review

import "bytes"

// Resource bounds of the line diff. They are part of the protocol: changing
// them changes the rendered request for some inputs.
const (
	// diffMaxD is the largest edit distance (number of inserted plus
	// deleted lines, after trimming the common prefix and suffix) for
	// which the minimal edit script is computed. Myers' algorithm keeps
	// one row of 2d+1 int32 per step, so memory is bounded by about
	// diffMaxD^2 * 4 bytes = 4 MiB.
	diffMaxD = 1024
	// diffMaxWork bounds the number of elementary steps (diagonal
	// visits plus line comparisons).
	diffMaxWork = 1 << 24
)

const noNewline = "\\ No newline at end of file\n"

// edit is one line of an edit script.
type edit struct {
	kind byte // ' ', '-' or '+'
	a, b int  // index into the old / new line slice (the one(s) that apply)
}

// splitLines splits data into lines, each including its terminating '\n'
// (the last line may lack one). '\r' is ordinary content. Empty input has
// zero lines.
func splitLines(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}
	lines := make([][]byte, 0, bytes.Count(data, []byte{'\n'})+1)
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			lines = append(lines, data)
			break
		}
		lines = append(lines, data[:i+1])
		data = data[i+1:]
	}
	return lines
}

// intern maps lines to small integers so that the diff compares integers.
// IDs are assigned in order of first appearance; the map is only used for
// lookups, so the result is deterministic.
func intern(al, bl [][]byte) (a, b []int32) {
	ids := make(map[string]int32, len(al)+len(bl))
	conv := func(lines [][]byte) []int32 {
		out := make([]int32, len(lines))
		for i, l := range lines {
			id, ok := ids[string(l)]
			if !ok {
				id = int32(len(ids))
				ids[string(l)] = id
			}
			out[i] = id
		}
		return out
	}
	return conv(al), conv(bl)
}

// diffLines returns an edit script transforming a into b. Inside every run
// of changes all deletions precede all insertions.
//
// The script is always VALID (applying it to a yields b). It is minimal
// whenever the edit distance of the part between the common prefix and the
// common suffix is at most diffMaxD and the work bound is not hit;
// otherwise that whole middle part is replaced ("delete all old lines, add
// all new lines"). The fallback is triggered by deterministic counters
// only - never by time or memory pressure - so all nodes agree.
func diffLines(a, b []int32) []edit {
	n, m := len(a), len(b)
	pre := 0
	for pre < n && pre < m && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < n-pre && suf < m-pre && a[n-1-suf] == b[m-1-suf] {
		suf++
	}
	out := make([]edit, 0, n+m-pre-suf)
	for i := 0; i < pre; i++ {
		out = append(out, edit{' ', i, i})
	}
	mid := myers(a[pre:n-suf], b[pre:m-suf])
	// Normalise: within each run of changes, deletions first.
	for i := 0; i < len(mid); {
		if mid[i].kind == ' ' {
			e := mid[i]
			out = append(out, edit{' ', e.a + pre, e.b + pre})
			i++
			continue
		}
		j := i
		for j < len(mid) && mid[j].kind != ' ' {
			j++
		}
		for k := i; k < j; k++ {
			if mid[k].kind == '-' {
				out = append(out, edit{'-', mid[k].a + pre, 0})
			}
		}
		for k := i; k < j; k++ {
			if mid[k].kind == '+' {
				out = append(out, edit{'+', 0, mid[k].b + pre})
			}
		}
		i = j
	}
	for i := 0; i < suf; i++ {
		out = append(out, edit{' ', n - suf + i, m - suf + i})
	}
	return out
}

// replaceAll is the fallback script.
func replaceAll(n, m int) []edit {
	out := make([]edit, 0, n+m)
	for i := 0; i < n; i++ {
		out = append(out, edit{'-', i, 0})
	}
	for j := 0; j < m; j++ {
		out = append(out, edit{'+', 0, j})
	}
	return out
}

// myers is the greedy O(ND) algorithm of E. Myers, "An O(ND) Difference
// Algorithm and Its Variations" (1986), with the rows of V recorded for
// backtracking.
func myers(a, b []int32) []edit {
	n, m := len(a), len(b)
	if n == 0 || m == 0 {
		return replaceAll(n, m)
	}
	dmax := n + m
	if dmax > diffMaxD {
		dmax = diffMaxD
	}
	off := dmax + 1
	v := make([]int32, 2*dmax+3)
	var trace [][]int32 // trace[d] = V[-d..d] after round d
	work := 0
	found := -1
search:
	for d := 0; d <= dmax; d++ {
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				x = int(v[off+k+1])
			} else {
				x = int(v[off+k-1]) + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
				work++
			}
			v[off+k] = int32(x)
			work++
			if x >= n && y >= m {
				found = d
				break search
			}
		}
		if work > diffMaxWork {
			break
		}
		row := make([]int32, 2*d+1)
		copy(row, v[off-d:off+d+1])
		trace = append(trace, row)
	}
	if found < 0 {
		return replaceAll(n, m)
	}

	// Backtrack from (n, m); the script is built in reverse.
	rev := make([]edit, 0, n+m)
	x, y := n, m
	for d := found; d > 0; d-- {
		prev := trace[d-1] // index k + (d-1)
		k := x - y
		var pk int
		if k == -d || (k != d && prev[k-1+d-1] < prev[k+1+d-1]) {
			pk = k + 1
		} else {
			pk = k - 1
		}
		px := int(prev[pk+d-1])
		py := px - pk
		for x > px && y > py {
			x--
			y--
			rev = append(rev, edit{' ', x, y})
		}
		if x == px {
			y--
			rev = append(rev, edit{'+', 0, y})
		} else {
			x--
			rev = append(rev, edit{'-', x, 0})
		}
	}
	for x > 0 && y > 0 {
		x--
		y--
		rev = append(rev, edit{' ', x, y})
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
}

// UnifiedDiff is the deterministic line diff used by BuildRequestBody. a
// and b are file contents; the result is the hunks: "@@ -l,s +l,s @@"
// headers followed by ' ', '-' and '+' prefixed lines, with
// "\ No newline at end of file" markers like GNU diff. Both counts are
// always written (also when they are 1); an empty range is written with
// the number of the line preceding it and count 0, as GNU diff and git do.
// Equal inputs yield an empty result. A negative context counts as 0.
func UnifiedDiff(a, b []byte, context int) []byte {
	if bytes.Equal(a, b) {
		return nil
	}
	if context < 0 {
		context = 0
	}
	al, bl := splitLines(a), splitLines(b)
	ai, bi := intern(al, bl)
	script := diffLines(ai, bi)

	var out []byte
	appendLine := func(prefix byte, line []byte) {
		out = append(out, prefix)
		out = append(out, line...)
		if len(line) == 0 || line[len(line)-1] != '\n' {
			out = append(out, '\n')
			out = append(out, noNewline...)
		}
	}
	appendInt := func(v int) {
		var tmp [20]byte
		i := len(tmp)
		if v == 0 {
			i--
			tmp[i] = '0'
		}
		for v > 0 {
			i--
			tmp[i] = byte('0' + v%10)
			v /= 10
		}
		out = append(out, tmp[i:]...)
	}

	// Positions (number of old / new lines consumed) before each edit.
	i := 0
	apos, bpos := 0, 0
	for i < len(script) {
		// Find the next change.
		for i < len(script) && script[i].kind == ' ' {
			i++
			apos++
			bpos++
		}
		if i >= len(script) {
			break
		}
		// The hunk starts up to `context` lines before it.
		start := i
		lead := 0
		for lead < context && start > 0 && script[start-1].kind == ' ' {
			start--
			lead++
		}
		// Extend the hunk while the gap to the next change is at most
		// 2*context equal lines.
		end := i
		for {
			for end < len(script) && script[end].kind != ' ' {
				end++
			}
			gap := end
			for gap < len(script) && script[gap].kind == ' ' && gap-end <= 2*context {
				gap++
			}
			if gap < len(script) && script[gap].kind != ' ' && gap-end <= 2*context {
				end = gap
				continue
			}
			// No further change close enough: trailing context.
			trail := gap - end
			if trail > context {
				trail = context
			}
			end += trail
			break
		}
		aStart, bStart := apos-lead, bpos-lead
		aCount, bCount := 0, 0
		for _, e := range script[start:end] {
			switch e.kind {
			case ' ':
				aCount++
				bCount++
			case '-':
				aCount++
			case '+':
				bCount++
			}
		}
		out = append(out, "@@ -"...)
		if aCount == 0 {
			appendInt(aStart)
		} else {
			appendInt(aStart + 1)
		}
		out = append(out, ',')
		appendInt(aCount)
		out = append(out, " +"...)
		if bCount == 0 {
			appendInt(bStart)
		} else {
			appendInt(bStart + 1)
		}
		out = append(out, ',')
		appendInt(bCount)
		out = append(out, " @@\n"...)
		for _, e := range script[start:end] {
			switch e.kind {
			case ' ':
				appendLine(' ', al[e.a])
			case '-':
				appendLine('-', al[e.a])
			case '+':
				appendLine('+', bl[e.b])
			}
		}
		// Advance the positions over the edits of this hunk that lie
		// at or after i (the lead was already counted).
		for _, e := range script[i:end] {
			switch e.kind {
			case ' ':
				apos++
				bpos++
			case '-':
				apos++
			case '+':
				bpos++
			}
		}
		i = end
	}
	return out
}
