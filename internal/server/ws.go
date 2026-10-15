package server

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	// Same-origin only in practice (loopback); allow since auth is by token.
	CheckOrigin: func(r *http.Request) bool { return true },
}

type hub struct {
	mu      sync.Mutex
	clients map[*client]struct{}
}

type client struct {
	conn *websocket.Conn
	send chan []byte
}

func newHub() *hub { return &hub{clients: map[*client]struct{}{}} }

type wsMsg struct {
	T string `json:"t"`
	D any    `json:"d"`
}

func (h *hub) broadcast(t string, d any) {
	b, err := json.Marshal(wsMsg{T: t, D: d})
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		select {
		case c.send <- b:
		default: // slow client: drop
		}
	}
}

func (h *hub) add(c *client) {
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
}

func (h *hub) remove(c *client) {
	h.mu.Lock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		close(c.send)
	}
	h.mu.Unlock()
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c := &client{conn: conn, send: make(chan []byte, 256)}
	s.hub.add(c)
	go func() {
		defer func() { s.hub.remove(c); conn.Close() }()
		for b := range c.send {
			if err := conn.WriteMessage(websocket.TextMessage, b); err != nil {
				return
			}
		}
	}()
	// Drain reads so control frames (close/ping) are handled.
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			s.hub.remove(c)
			conn.Close()
			return
		}
	}
}
