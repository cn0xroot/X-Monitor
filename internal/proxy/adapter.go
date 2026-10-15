// Package proxy is the L4 LLM API proxy (DESIGN.md §7). Protocol adapters turn
// a streamed assistant response into a sequence of tool calls, let the gate
// vet each one, and rewrite the stream so blocked calls become an explanatory
// assistant message instead of an executed tool call.
package proxy

import "xmonitor/internal/toolclass"

// ToolCall is one assembled tool call from a response stream.
type ToolCall struct {
	Index int
	ID    string
	Name  string
	Args  string // accumulated JSON argument text
}

// ToClass normalizes the tool call to one or more canonical calls.
func (t ToolCall) ToClass() []toolclass.Call {
	return toolclass.Normalize(t.ID, t.Name, toolclass.ParseArgs(t.Args))
}

// Decision is what the proxy decided for one tool call.
type Decision struct {
	Block   bool
	Message string // assistant text to emit when Block is true
}

// Adapter rewrites one provider's streaming (and non-streaming) format.
// Implementations are in adapter_*.go.
type Adapter interface {
	// Name identifies the wire format.
	Name() string
	// RewriteStream reads an SSE body, calls decide for each completed tool
	// call, and writes the (possibly rewritten) stream to out. flush is
	// called after each write so bytes reach the client promptly.
	RewriteStream(body []byte, decide func(ToolCall) Decision, out Writer) error
	// RewriteJSON does the same for a non-streamed JSON response.
	RewriteJSON(body []byte, decide func(ToolCall) Decision) ([]byte, error)
	// ExtractRequest pulls the user goal and any tool_result text (untrusted
	// content headed to the model) from a request body, for §7.5/§7.6.
	ExtractRequest(body []byte) RequestInfo
}

// Writer receives rewritten stream bytes.
type Writer interface {
	Write(p []byte) (int, error)
	Flush()
}

// RequestInfo is what the request side contributes.
type RequestInfo struct {
	UserGoal    string   // first user instruction
	Model       string   // requested model
	Egress      []string // text blocks about to be sent to the model (tool results, user msgs)
	ToolResults []string // results from untrusted sources (fetch/read)
}

// knownProviders maps a path prefix to a format when routing is ambiguous.
func adapterFor(name string) Adapter {
	switch name {
	case "anthropic":
		return anthropicAdapter{}
	case "gemini":
		return geminiAdapter{}
	case "openai-responses":
		return openaiResponsesAdapter{}
	default:
		return openaiChatAdapter{}
	}
}
