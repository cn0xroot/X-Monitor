package proxy

import (
	"encoding/json"
	"fmt"
)

// anthropicAdapter handles the Anthropic Messages API (/v1/messages).
//
// Streaming shape: content_block_start{type:tool_use,id,name} →
// content_block_delta{input_json_delta}* → content_block_stop; the final
// message_delta carries stop_reason=tool_use. We buffer each tool_use block,
// decide when it stops, and either replay the original events (allow) or emit
// a text block in its place (block). See DESIGN.md §7.4.
type anthropicAdapter struct{}

func (anthropicAdapter) Name() string { return "anthropic" }

type antBlock struct {
	index    int
	isTool   bool
	buffered []sseEvent // start + deltas + stop, replayed verbatim on allow
	tc       ToolCall
}

func (a anthropicAdapter) RewriteStream(body []byte, decide func(ToolCall) Decision, out Writer) error {
	events := parseSSE(body)
	var cur *antBlock
	blockedAny := false
	anyText := false // did any tool_use survive? (keeps stop_reason=tool_use)

	for _, ev := range events {
		var probe struct {
			Type         string `json:"type"`
			Index        int    `json:"index"`
			ContentBlock struct {
				Type string `json:"type"`
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"content_block"`
			Delta struct {
				Type        string `json:"type"`
				PartialJSON string `json:"partial_json"`
				StopReason  string `json:"stop_reason"`
			} `json:"delta"`
		}
		_ = json.Unmarshal(ev.data, &probe)

		switch probe.Type {
		case "content_block_start":
			if probe.ContentBlock.Type == "tool_use" {
				cur = &antBlock{index: probe.Index, isTool: true, buffered: []sseEvent{ev}}
				cur.tc = ToolCall{Index: probe.Index, ID: probe.ContentBlock.ID, Name: probe.ContentBlock.Name}
				continue // buffer, don't emit yet
			}
			writeRaw(out, ev.raw)
		case "content_block_delta":
			if cur != nil && cur.isTool && probe.Index == cur.index {
				cur.tc.Args += probe.Delta.PartialJSON
				cur.buffered = append(cur.buffered, ev)
				continue
			}
			writeRaw(out, ev.raw)
		case "content_block_stop":
			if cur != nil && cur.isTool && probe.Index == cur.index {
				cur.buffered = append(cur.buffered, ev)
				d := decide(cur.tc)
				if d.Block {
					blockedAny = true
					a.emitTextBlock(out, cur.index, d.Message)
				} else {
					anyText = true
					for _, b := range cur.buffered {
						writeRaw(out, b.raw)
					}
				}
				cur = nil
				continue
			}
			writeRaw(out, ev.raw)
		case "message_delta":
			// If everything that was a tool_use got blocked, end the turn so
			// the agent stops instead of trying to execute nothing.
			if blockedAny && !anyText {
				patched := patchStopReason(ev.data, "end_turn")
				writeEvent(out, ev.event, patched)
				continue
			}
			writeRaw(out, ev.raw)
		default:
			writeRaw(out, ev.raw)
		}
	}
	return nil
}

// emitTextBlock writes a full text content block (start/delta/stop) at index.
func (anthropicAdapter) emitTextBlock(out Writer, index int, text string) {
	start, _ := json.Marshal(map[string]any{
		"type": "content_block_start", "index": index,
		"content_block": map[string]any{"type": "text", "text": ""},
	})
	writeEvent(out, "content_block_start", start)
	delta, _ := json.Marshal(map[string]any{
		"type": "content_block_delta", "index": index,
		"delta": map[string]any{"type": "text_delta", "text": text},
	})
	writeEvent(out, "content_block_delta", delta)
	stop, _ := json.Marshal(map[string]any{"type": "content_block_stop", "index": index})
	writeEvent(out, "content_block_stop", stop)
}

func patchStopReason(data []byte, reason string) []byte {
	var m map[string]any
	if json.Unmarshal(data, &m) != nil {
		return data
	}
	if d, ok := m["delta"].(map[string]any); ok {
		d["stop_reason"] = reason
	}
	b, _ := json.Marshal(m)
	return b
}

func (a anthropicAdapter) RewriteJSON(body []byte, decide func(ToolCall) Decision) ([]byte, error) {
	var msg struct {
		Content    []map[string]any `json:"content"`
		StopReason string           `json:"stop_reason"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		return body, nil
	}
	blockedAny, anyTool := false, false
	for i, block := range msg.Content {
		if block["type"] != "tool_use" {
			continue
		}
		args, _ := json.Marshal(block["input"])
		id, _ := block["id"].(string)
		name, _ := block["name"].(string)
		d := decide(ToolCall{Index: i, ID: id, Name: name, Args: string(args)})
		if d.Block {
			blockedAny = true
			msg.Content[i] = map[string]any{"type": "text", "text": d.Message}
		} else {
			anyTool = true
		}
	}
	if !blockedAny {
		return body, nil
	}
	// Reparse into the full object to preserve unknown top-level fields.
	var full map[string]any
	_ = json.Unmarshal(body, &full)
	full["content"] = msg.Content
	if !anyTool {
		full["stop_reason"] = "end_turn"
	}
	return json.Marshal(full)
}

func (anthropicAdapter) ExtractRequest(body []byte) RequestInfo {
	var req struct {
		Model    string `json:"model"`
		System   any    `json:"system"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if json.Unmarshal(body, &req) != nil {
		return RequestInfo{}
	}
	info := RequestInfo{Model: req.Model}
	for _, m := range req.Messages {
		// content may be a plain string or an array of blocks.
		var s string
		if json.Unmarshal(m.Content, &s) == nil {
			if m.Role == "user" && info.UserGoal == "" {
				info.UserGoal = s
			}
			if m.Role == "user" {
				info.Egress = append(info.Egress, s)
			}
			continue
		}
		var blocks []map[string]any
		if json.Unmarshal(m.Content, &blocks) != nil {
			continue
		}
		for _, b := range blocks {
			switch b["type"] {
			case "text":
				t, _ := b["text"].(string)
				if m.Role == "user" {
					if info.UserGoal == "" {
						info.UserGoal = t
					}
					info.Egress = append(info.Egress, t)
				}
			case "tool_result":
				t := stringifyContent(b["content"])
				info.ToolResults = append(info.ToolResults, t)
				info.Egress = append(info.Egress, t)
			}
		}
	}
	return info
}

func stringifyContent(v any) string {
	switch c := v.(type) {
	case string:
		return c
	case []any:
		out := ""
		for _, x := range c {
			if m, ok := x.(map[string]any); ok {
				if t, ok := m["text"].(string); ok {
					out += t + "\n"
				}
			}
		}
		return out
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

var _ = fmt.Sprintf
