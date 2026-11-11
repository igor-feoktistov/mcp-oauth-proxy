package graph

import (
	"container/list"
	"sync"
	"time"
)

// entry is one cached group-membership lookup. A non-nil err marks a negative
// entry, which exists so that a Graph outage cannot turn into a request storm.
type entry struct {
	groups    []Group
	err       error
	fetchedAt time.Time
	expiresAt time.Time
}

func (e *entry) fresh(now time.Time) bool { return now.Before(e.expiresAt) }

// lruCache is a size-bounded cache. Without a bound the map would grow with
// every distinct user object id the proxy ever sees.
type lruCache struct {
	mu      sync.Mutex
	maxSize int
	items   map[string]*list.Element
	order   *list.List // front = most recently used
}

type lruItem struct {
	key string
	val *entry
}

func newLRU(maxSize int) *lruCache {
	if maxSize < 1 {
		maxSize = 1
	}
	return &lruCache{
		maxSize: maxSize,
		items:   make(map[string]*list.Element, maxSize),
		order:   list.New(),
	}
}

func (c *lruCache) get(key string) (*entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*lruItem).val, true
}

func (c *lruCache) put(key string, e *entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		el.Value.(*lruItem).val = e
		c.order.MoveToFront(el)
		return
	}
	c.items[key] = c.order.PushFront(&lruItem{key: key, val: e})
	for c.order.Len() > c.maxSize {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		c.order.Remove(oldest)
		delete(c.items, oldest.Value.(*lruItem).key)
	}
}

func (c *lruCache) delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.order.Remove(el)
		delete(c.items, key)
	}
}

func (c *lruCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// flight deduplicates concurrent lookups for the same key so that a burst of
// requests from one user produces a single Graph call.
type flight struct {
	mu    sync.Mutex
	calls map[string]*call
}

type call struct {
	done   chan struct{}
	groups []Group
	err    error
}

func newFlight() *flight { return &flight{calls: make(map[string]*call)} }

// do runs fn for key, or waits for the in-flight call that is already running it.
func (f *flight) do(key string, fn func() ([]Group, error)) ([]Group, error) {
	f.mu.Lock()
	if c, ok := f.calls[key]; ok {
		f.mu.Unlock()
		<-c.done
		return c.groups, c.err
	}
	c := &call{done: make(chan struct{})}
	f.calls[key] = c
	f.mu.Unlock()

	defer func() {
		f.mu.Lock()
		delete(f.calls, key)
		f.mu.Unlock()
		close(c.done)
	}()

	c.groups, c.err = fn()
	return c.groups, c.err
}
