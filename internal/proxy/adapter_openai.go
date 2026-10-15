package proxy

import (
	"encoding/json"
	"fmt"
	"sort"
)

// openaiChatAdapter handles OpenAI Chat Completions and every compatible API
// (GLM / Zhipu, DeepSeek, OpenRouter, …).
//
// Streaming shape: choices[].delta.tool_calls[{index,id,function{name,arguments}}]
// accumulate across chunks; finish_reason=tool_calls ends the turn. Unlike
// Anthropic, tool-call deltas and text can't be cleanly separated mid-stream,
// so we buffer the whole response, decide, and emit a rewritten tail. Text
// deltas seen before any tool call are streamed through immediately.
type openaiChatAdapter struct{}

func (openaiChatAdapter) Name() string { return "openai-chat" }

func (a openaiChatAdapter) RewriteStream(body []byte, decide func(ToolCall) Decision, out Writer) error {
	events := parseSSE(body)
	calls := map[int]*ToolCall{}
	var tail []sseEvent // events from the first tool-call chunk onward
	buffering := false
	var model, id string

	for _, ev := range events {
		if string(ev.data) == "[DONE]" {
			break
		}
		var chunk struct {
			ID      string `json:"id"`
			Model   string `json:"model"`
			Choices []struct {
				Delta struct {
					Content   string `json:"content"`
					ToolCalls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
		}
		if json.Unmarshal(ev.data, &chunk) != nil {
			if !buffering {
				writeRaw(out, ev.raw)
			} else {
				tail = append(tail, ev)
			}
			continue
		}
		if chunk.ID != "" {
			id = chunk.ID
		}
		if chunk.Model != "" {
			model = chunk.Model
		}
		hasTool := false
		for _, ch := range chunk.Choices {
			for _, tc := range ch.Delta.ToolCalls {
				hasTool = true
				c := calls[tc.Index]
				if c == nil {
					c = &ToolCall{Index: tc.Index}
					calls[tc.Index] = c
				}
				if tc.ID != "" {
					c.ID = tc.ID
				}
				if tc.Function.Name != "" {
					c.Name = tc.Function.Name
				}
				c.Args += tc.Function.Arguments
			}
		}
		if hasTool {
			buffering = true
		}
		if buffering {
			tail = append(tail, ev)
		} else {
			writeRaw(out, ev.raw) // plain text delta: stream through
		}
	}

	if len(calls) == 0 {
		// No tool calls: replay the tail (there was none) and finish.
		writeEvent(out, "", []byte("[DONE]"))
		return nil
	}

	idxs := sortedKeys(calls)
	decisions := map[int]Decision{}
	blockedAny, allowedAny := false, false
	for _, i := range idxs {
		d := decide(*calls[i])
		decisions[i] = d
		if d.Block {
			blockedAny = true
		} else {
			allowedAny = true
		}
	}

	if !blockedAny {
		for _, ev := range tail {
			writeRaw(out, ev.raw)
		}
		writeEvent(out, "", []byte("[DONE]"))
		return nil
	}

	// Emit allowed tool calls, then a text chunk for blocked ones.
	a.emitRewritten(out, id, model, idxs, calls, decisions, allowedAny)
	writeEvent(out, "", []byte("[DONE]"))
	return nil
}

func (openaiChatAdapter) emitRewritten(out Writer, id, model string, idxs []int, calls map[int]*ToolCall, decisions map[int]Decision, allowedAny bool) {
	var toolDeltas []map[string]any
	var blockedMsgs string
	newIdx := 0
	for _, i := range idxs {
		if decisions[i].Block {
			if blockedMsgs != "" {
				blockedMsgs += "\n"
			}
			blockedMsgs += decisions[i].Message
			continue
		}
		c := calls[i]
		toolDeltas = append(toolDeltas, map[string]any{
			"index": newIdx, "id": c.ID, "type": "function",
			"function": map[string]any{"name": c.Name, "arguments": c.Args},
		})
		newIdx++
	}
	emit := func(delta map[string]any, finish any) {
		chunk := map[string]any{
			"id": id, "object": "chat.completion.chunk", "model": model,
			"choices": []map[string]any{{"index": 0, "delta": delta, "finish_reason": finish}},
		}
		b, _ := json.Marshal(chunk)
		writeEvent(out, "", b)
	}
	if blockedMsgs != "" {
		emit(map[string]any{"role": "assistant", "content": blockedMsgs}, nil)
	}
	if len(toolDeltas) > 0 {
		emit(map[string]any{"tool_calls": toolDeltas}, nil)
		emit(map[string]any{}, "tool_calls")
	} else {
		emit(map[string]any{}, "stop")
	}
}

func (a openaiChatAdapter) RewriteJSON(body []byte, decide func(ToolCall) Decision) ([]byte, error) {
	var full map[string]any
	if json.Unmarshal(body, &full) != nil {
		return body, nil
	}
	choices, _ := full["choices"].([]any)
	changed := false
	for _, ch := range choices {
		choice, _ := ch.(map[string]any)
		if choice == nil {
			continue
		}
		msg, _ := choice["message"].(map[string]any)
		if msg == nil {
			continue
		}
		tcs, _ := msg["tool_calls"].([]any)
		if len(tcs) == 0 {
			continue
		}
		var kept []any
		var blockedMsgs string
		for i, raw := range tcs {
			tc, _ := raw.(map[string]any)
			fn, _ := tc["function"].(map[string]any)
			name, _ := fn["name"].(string)
			args, _ := fn["arguments"].(string)
			id, _ := tc["id"].(string)
			d := decide(ToolCall{Index: i, ID: id, Name: name, Args: args})
			if d.Block {
				changed = true
				if blockedMsgs != "" {
					blockedMsgs += "\n"
				}
				blockedMsgs += d.Message
			} else {
				kept = append(kept, raw)
			}
		}
		if !changed {
			continue
		}
		if len(kept) > 0 {
			msg["tool_calls"] = kept
		} else {
			delete(msg, "tool_calls")
			choice["finish_reason"] = "stop"
		}
		if blockedMsgs != "" {
			if existing, _ := msg["content"].(string); existing != "" {
				msg["content"] = existing + "\n" + blockedMsgs
			} else {
				msg["content"] = blockedMsgs
			}
		}
	}
	if !changed {
		return body, nil
	}
	return json.Marshal(full)
}

func (openaiChatAdapter) ExtractRequest(body []byte) RequestInfo {
	var req struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
			Name    string          `json:"name"`
		} `json:"messages"`
	}
	if json.Unmarshal(body, &req) != nil {
		return RequestInfo{}
	}
	info := RequestInfo{Model: req.Model}
	for _, m := range req.Messages {
		var s string
		if json.Unmarshal(m.Content, &s) != nil {
			s = stringifyContent(jsonAny(m.Content))
		}
		switch m.Role {
		case "user":
			if info.UserGoal == "" {
				info.UserGoal = s
			}
			info.Egress = append(info.Egress, s)
		case "tool":
			info.ToolResults = append(info.ToolResults, s)
			info.Egress = append(info.Egress, s)
		}
	}
	return info
}

func jsonAny(raw json.RawMessage) any {
	var v any
	_ = json.Unmarshal(raw, &v)
	return v
}

func sortedKeys(m map[int]*ToolCall) []int {
	ks := make([]int, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Ints(ks)
	return ks
}

var _ = fmt.Sprintf
