package proxy

import "encoding/json"

// geminiAdapter handles Google's generateContent / streamGenerateContent API.
// This is the format Gemini CLI speaks, including the Z.ai CLI, which is Gemini
// CLI pointed at a Z.ai endpoint (https://docs.z.ai gemini scenario). Tool calls
// appear as a complete functionCall part inside a candidate's content — args is
// a full JSON object, not streamed incrementally like OpenAI — so each SSE chunk
// is a self-contained GenerateContentResponse we can inspect and rewrite.
type geminiAdapter struct{}

func (geminiAdapter) Name() string { return "gemini" }

type gemChunk struct {
	Candidates []struct {
		Content struct {
			Role  string           `json:"role"`
			Parts []map[string]any `json:"parts"`
		} `json:"content"`
		FinishReason string `json:"finishReason"`
	} `json:"candidates"`
}

func (a geminiAdapter) RewriteStream(body []byte, decide func(ToolCall) Decision, out Writer) error {
	for _, ev := range parseSSE(body) {
		var c gemChunk
		if json.Unmarshal(ev.data, &c) != nil || len(c.Candidates) == 0 {
			writeRaw(out, ev.raw)
			continue
		}
		rewritten, changed := a.rewriteChunk(&c, ev.data, decide)
		if changed {
			writeEvent(out, ev.event, rewritten)
		} else {
			writeRaw(out, ev.raw)
		}
	}
	return nil
}

// rewriteChunk replaces blocked functionCall parts with a text part.
func (a geminiAdapter) rewriteChunk(c *gemChunk, raw []byte, decide func(ToolCall) Decision) ([]byte, bool) {
	var full map[string]any
	if json.Unmarshal(raw, &full) != nil {
		return raw, false
	}
	cands, _ := full["candidates"].([]any)
	changed := false
	for ci := range cands {
		cand, _ := cands[ci].(map[string]any)
		content, _ := cand["content"].(map[string]any)
		if content == nil {
			continue
		}
		parts, _ := content["parts"].([]any)
		var newParts []any
		for _, p := range parts {
			part, _ := p.(map[string]any)
			fc, _ := part["functionCall"].(map[string]any)
			if fc == nil {
				newParts = append(newParts, p)
				continue
			}
			name, _ := fc["name"].(string)
			args, _ := json.Marshal(fc["args"])
			d := decide(ToolCall{Name: name, Args: string(args)})
			if d.Block {
				changed = true
				newParts = append(newParts, map[string]any{"text": d.Message})
			} else {
				newParts = append(newParts, p)
			}
		}
		if changed {
			content["parts"] = newParts
			// If nothing executable remains, let the turn end normally.
			cand["finishReason"] = "STOP"
		}
	}
	if !changed {
		return raw, false
	}
	b, _ := json.Marshal(full)
	return b, true
}

func (a geminiAdapter) RewriteJSON(body []byte, decide func(ToolCall) Decision) ([]byte, error) {
	var c gemChunk
	if json.Unmarshal(body, &c) != nil {
		return body, nil
	}
	rewritten, changed := a.rewriteChunk(&c, body, decide)
	if !changed {
		return body, nil
	}
	return rewritten, nil
}

func (geminiAdapter) ExtractRequest(body []byte) RequestInfo {
	var req struct {
		Contents []struct {
			Role  string           `json:"role"`
			Parts []map[string]any `json:"parts"`
		} `json:"contents"`
	}
	if json.Unmarshal(body, &req) != nil {
		return RequestInfo{}
	}
	var info RequestInfo
	for _, m := range req.Contents {
		for _, part := range m.Parts {
			if t, ok := part["text"].(string); ok {
				if m.Role == "user" {
					if info.UserGoal == "" {
						info.UserGoal = t
					}
					info.Egress = append(info.Egress, t)
				}
			}
			if fr, ok := part["functionResponse"].(map[string]any); ok {
				b, _ := json.Marshal(fr["response"])
				info.ToolResults = append(info.ToolResults, string(b))
				info.Egress = append(info.Egress, string(b))
			}
		}
	}
	return info
}
