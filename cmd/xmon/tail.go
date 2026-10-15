package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"xmonitor/internal/config"
	"xmonitor/internal/event"
)

// uiClient dials the dashboard API over loopback TCP with the stored token.
func uiClient() (base, token string, cl *http.Client, err error) {
	cfg, _ := config.Load()
	token, err = config.Token()
	if err != nil {
		return
	}
	base = "http://" + cfg.UIAddr
	cl = &http.Client{Timeout: 5 * time.Second,
		// Never route the daemon's own loopback through an ambient HTTP proxy.
		Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}}
	return
}

func rankOf(r string) int { return event.Risk(r).Rank() }

func printEvent(e *event.Event, min int) {
	if rankOf(string(e.Risk)) < min {
		return
	}
	ts := time.UnixMilli(e.TS).Format("15:04:05")
	tool := ""
	if e.Tool != nil {
		tool = e.Tool.Raw
	}
	fmt.Printf("%s [%-2s] %-9s %-7s %-8s %s %s\n", ts, e.Layer, e.Risk, e.Decision, tool, e.Rule, e.Title)
}

func tailEvents(follow bool, minRisk string) error {
	base, token, cl, err := uiClient()
	if err != nil {
		return err
	}
	min := rankOf(minRisk)
	// Backlog first.
	req, _ := http.NewRequest("GET", base+"/api/events?limit=40&token="+token, nil)
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("daemon API unreachable: %w", err)
	}
	var evs []*event.Event
	_ = json.NewDecoder(resp.Body).Decode(&evs)
	resp.Body.Close()
	for i := len(evs) - 1; i >= 0; i-- {
		printEvent(evs[i], min)
	}
	if !follow {
		return nil
	}
	// Live follow over WebSocket.
	d := websocket.Dialer{Proxy: nil, HandshakeTimeout: 5 * time.Second}
	wsURL := "ws://" + mustHostPort(base) + "/ws?token=" + token
	conn, _, err := d.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("ws connect: %w", err)
	}
	defer conn.Close()
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return nil
		}
		var m struct {
			T string          `json:"t"`
			D json.RawMessage `json:"d"`
		}
		if json.Unmarshal(data, &m) != nil || m.T != "event" {
			continue
		}
		var e event.Event
		if json.Unmarshal(m.D, &e) == nil {
			printEvent(&e, min)
		}
	}
}

func mustHostPort(base string) string {
	return base[len("http://"):]
}
