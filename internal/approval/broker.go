// Package approval is the confirmation workflow (DESIGN.md §14): a pending
// approval is persisted, announced (desktop notification / Web UI / CLI), and
// the caller blocks until it is resolved or times out (default: deny).
package approval

import (
	"context"
	"errors"
	"sync"
	"time"

	"xmonitor/internal/store"
)

// Decision values accepted by Resolve.
const (
	AllowOnce    = "allow_once"
	AllowSession = "allow_session"
	Deny         = "deny"
)

// Result is how an approval ended.
type Result struct {
	Allowed bool
	Scope   string // once | session
	Status  string // allowed | denied | expired
	Via     string
}

// Notifier announces a new pending approval (best effort).
type Notifier func(a *store.Approval)

// Broker coordinates waiters and resolvers.
type Broker struct {
	st      *store.Store
	timeout func() time.Duration
	notify  Notifier

	mu      sync.Mutex
	waiters map[int64]chan Result
	subs    map[chan struct{}]struct{}
}

// New creates a broker.
func New(st *store.Store, timeout func() time.Duration, n Notifier) *Broker {
	return &Broker{st: st, timeout: timeout, notify: n, waiters: map[int64]chan Result{}, subs: map[chan struct{}]struct{}{}}
}

// Request creates a pending approval and waits for it.
func (b *Broker) Request(ctx context.Context, a *store.Approval) (Result, error) {
	if _, err := b.st.CreateApproval(a); err != nil {
		return Result{Status: "denied", Via: "error"}, err
	}
	ch := make(chan Result, 1)
	b.mu.Lock()
	b.waiters[a.ID] = ch
	b.mu.Unlock()
	b.broadcast()
	if b.notify != nil {
		go b.notify(a)
	}
	t := time.NewTimer(b.timeout())
	defer t.Stop()
	select {
	case r := <-ch:
		return r, nil
	case <-t.C:
		b.finish(a.ID, Result{Status: "expired", Via: "timeout"})
		return Result{Status: "expired", Via: "timeout"}, nil
	case <-ctx.Done():
		b.finish(a.ID, Result{Status: "expired", Via: "cancelled"})
		return Result{Status: "expired", Via: "cancelled"}, ctx.Err()
	}
}

// ErrUnknown is returned for approvals that no one is waiting on.
var ErrUnknown = errors.New("no such pending approval")

// Resolve answers a pending approval.
func (b *Broker) Resolve(id int64, decision, via string) error {
	var r Result
	switch decision {
	case AllowOnce:
		r = Result{Allowed: true, Scope: "once", Status: "allowed", Via: via}
	case AllowSession:
		r = Result{Allowed: true, Scope: "session", Status: "allowed", Via: via}
	case Deny:
		r = Result{Status: "denied", Via: via}
	default:
		return errors.New("decision must be allow_once, allow_session or deny")
	}
	b.mu.Lock()
	ch, ok := b.waiters[id]
	b.mu.Unlock()
	if !ok {
		return ErrUnknown
	}
	if err := b.st.ResolveApproval(id, r.Status, via); err != nil {
		return err
	}
	b.mu.Lock()
	delete(b.waiters, id)
	b.mu.Unlock()
	ch <- r
	b.broadcast()
	return nil
}

func (b *Broker) finish(id int64, r Result) {
	b.mu.Lock()
	_, ok := b.waiters[id]
	delete(b.waiters, id)
	b.mu.Unlock()
	if ok {
		_ = b.st.ResolveApproval(id, r.Status, r.Via)
		b.broadcast()
	}
}

// Subscribe returns a channel signalled whenever the pending set changes.
func (b *Broker) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
	}
}

func (b *Broker) broadcast() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
