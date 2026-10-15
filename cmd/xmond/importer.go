package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"time"

	"xmonitor/internal/event"
	"xmonitor/internal/gate"
	"xmonitor/internal/importer"
	"xmonitor/internal/store"
)

// metaKey returns the dedup watermark key for a given source DB path.
func ccMetaKey(path string) string {
	h := sha256.Sum256([]byte(path))
	return "ccimport_lastid_" + hex.EncodeToString(h[:6])
}

// runImport pulls new CC-Monitor rows into the store once. Returns how many
// were imported. Imported events join the hash chain as normal audit records,
// tagged imported_from=cc-monitor and deduped by the original row id.
func runImport(st *store.Store, g *gate.Gate, path string) (int, error) {
	src, err := importer.Open(path)
	if err != nil {
		return 0, err
	}
	defer src.Close()
	key := ccMetaKey(path)
	last := parseInt64(st.Meta(key))
	total := 0
	for {
		batch, err := src.Fetch(last, 500)
		if err != nil {
			return total, err
		}
		if len(batch) == 0 {
			break
		}
		for _, m := range batch {
			g.Emit(m.Event)
			last = m.OrigID
			total++
		}
		_ = st.SetMeta(key, formatInt64(last))
	}
	return total, nil
}

// followImport keeps importing on an interval until ctx is cancelled.
func followImport(ctx context.Context, st *store.Store, g *gate.Gate, path string) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := runImport(st, g, path); err != nil {
				log.Printf("cc-monitor import: %v", err)
			} else if n > 0 {
				log.Printf("cc-monitor import: +%d events", n)
			}
		}
	}
}

var _ = event.LayerHook

func parseInt64(s string) int64 {
	var n int64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0
		}
		n = n*10 + int64(s[i]-'0')
	}
	return n
}

func formatInt64(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
