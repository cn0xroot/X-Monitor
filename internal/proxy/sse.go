package proxy

import (
	"bufio"
	"bytes"
	"strings"
)

// sseEvent is one parsed Server-Sent Event.
type sseEvent struct {
	event string
	data  []byte
	raw   []byte // original bytes including the trailing blank line
}

// parseSSE splits an SSE body into events, preserving each event's raw bytes so
// pass-through is byte-exact.
func parseSSE(body []byte) []sseEvent {
	var out []sseEvent
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	sc.Split(scanSSEBlocks)
	for sc.Scan() {
		block := sc.Bytes()
		ev := sseEvent{raw: append([]byte(nil), block...)}
		for _, line := range strings.Split(string(block), "\n") {
			switch {
			case strings.HasPrefix(line, "event:"):
				ev.event = strings.TrimSpace(line[6:])
			case strings.HasPrefix(line, "data:"):
				d := line[5:]
				if strings.HasPrefix(d, " ") {
					d = d[1:]
				}
				if len(ev.data) > 0 {
					ev.data = append(ev.data, '\n')
				}
				ev.data = append(ev.data, d...)
			}
		}
		out = append(out, ev)
	}
	return out
}

// scanSSEBlocks is a bufio.SplitFunc that returns one event block per call
// (everything up to and including a blank line separator).
func scanSSEBlocks(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		return i + 2, data[:i], nil
	}
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		return i + 4, data[:i], nil
	}
	if atEOF {
		return len(data), dropTrailingNewlines(data), nil
	}
	return 0, nil, nil
}

func dropTrailingNewlines(b []byte) []byte {
	return bytes.TrimRight(b, "\r\n")
}

// writeEvent writes an SSE event (event: line optional) and flushes.
func writeEvent(out Writer, event string, data []byte) {
	var b bytes.Buffer
	if event != "" {
		b.WriteString("event: ")
		b.WriteString(event)
		b.WriteByte('\n')
	}
	b.WriteString("data: ")
	b.Write(data)
	b.WriteString("\n\n")
	_, _ = out.Write(b.Bytes())
	out.Flush()
}

func writeRaw(out Writer, raw []byte) {
	_, _ = out.Write(raw)
	_, _ = out.Write([]byte("\n\n"))
	out.Flush()
}
