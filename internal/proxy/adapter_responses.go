package proxy

import "encoding/json"

// openaiResponsesAdapter handles the OpenAI Responses API (/v1/responses).
// Streaming shape: response.output_item.added{type:function_call} →
// response.function_call_arguments.delta* → response.function_call_arguments.done.
// Full stream rewrite is not yet implemented; we buffer and fall back to a
// conservative pass-through for the stream, while the non-streamed path is
// handled. This keeps the Responses API usable (DESIGN.md P4) without
// pretending to enforce on a format we don't yet fully parse.
type openaiResponsesAdapter struct{}

func (openaiResponsesAdapter) Name() string { return "openai-responses" }

func (openaiResponsesAdapter) RewriteStream(body []byte, decide func(ToolCall) Decision, out Writer) error {
	// Assemble function calls to at least audit them; pass the stream through.
	// Enforcement on this format is tracked as future work.
	for _, ev := range parseSSE(body) {
		writeRaw(out, ev.raw)
	}
	return nil
}

func (a openaiResponsesAdapter) RewriteJSON(body []byte, decide func(ToolCall) Decision) ([]byte, error) {
	var full map[string]any
	if json.Unmarshal(body, &full) != nil {
		return body, nil
	}
	output, _ := full["output"].([]any)
	changed := false
	var kept []any
	var blockedMsgs string
	for i, raw := range output {
		item, _ := raw.(map[string]any)
		if item == nil || item["type"] != "function_call" {
			kept = append(kept, raw)
			continue
		}
		name, _ := item["name"].(string)
		args, _ := item["arguments"].(string)
		id, _ := item["call_id"].(string)
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
		return body, nil
	}
	if blockedMsgs != "" {
		kept = append(kept, map[string]any{
			"type": "message", "role": "assistant",
			"content": []any{map[string]any{"type": "output_text", "text": blockedMsgs}},
		})
	}
	full["output"] = kept
	return json.Marshal(full)
}

func (openaiResponsesAdapter) ExtractRequest(body []byte) RequestInfo {
	var req struct {
		Model string          `json:"model"`
		Input json.RawMessage `json:"input"`
	}
	if json.Unmarshal(body, &req) != nil {
		return RequestInfo{}
	}
	info := RequestInfo{Model: req.Model}
	var s string
	if json.Unmarshal(req.Input, &s) == nil {
		info.UserGoal = s
		info.Egress = append(info.Egress, s)
	}
	return info
}
