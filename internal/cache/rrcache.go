package cache

import (
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

type rrKey struct {
	Name string
	Type uint16
}

type negKey struct {
	Name  string
	Type  uint16
	Rcode int
}

type rrValue[T any] struct {
	ExpireAt time.Time
	Data     T
}

type RRCaches[T any] struct {
	posMu sync.Mutex
	negMu sync.Mutex
	pos   *lru.Cache[rrKey, rrValue[T]]
	neg   *lru.Cache[negKey, rrValue[struct{}]]
}

func NewRRCaches[T any](capacity int) (*RRCaches[T], error) {
	pos, err := lru.New[rrKey, rrValue[T]](capacity)
	if err != nil {
		return nil, err
	}
	neg, err := lru.New[negKey, rrValue[struct{}]](capacity / 10)
	if err != nil {
		return nil, err
	}
	return &RRCaches[T]{pos: pos, neg: neg}, nil
}

func (c *RRCaches[T]) key(name string, qtype uint16) rrKey {
	return rrKey{Name: strings.ToLower(name), Type: qtype}
}

func (c *RRCaches[T]) GetPositive(name string, qtype uint16) (T, bool) {
	var zero T
	c.posMu.Lock()
	defer c.posMu.Unlock()
	if v, ok := c.pos.Get(c.key(name, qtype)); ok {
		if time.Now().Before(v.ExpireAt) {
			return v.Data, true
		}
		c.pos.Remove(c.key(name, qtype))
	}
	return zero, false
}

func (c *RRCaches[T]) PutPositive(name string, qtype uint16, data T, ttl time.Duration) {
	c.posMu.Lock()
	defer c.posMu.Unlock()
	c.pos.Add(c.key(name, qtype), rrValue[T]{ExpireAt: time.Now().Add(ttl), Data: data})
}

func (c *RRCaches[T]) GetNegative(name string, qtype uint16, rcode int) bool {
	c.negMu.Lock()
	defer c.negMu.Unlock()
	k := negKey{Name: strings.ToLower(name), Type: qtype, Rcode: rcode}
	if v, ok := c.neg.Get(k); ok {
		if time.Now().Before(v.ExpireAt) {
			return true
		}
		c.neg.Remove(k)
	}
	return false
}

func (c *RRCaches[T]) PutNegative(name string, qtype uint16, rcode int, ttl time.Duration) {
	c.negMu.Lock()
	defer c.negMu.Unlock()
	c.neg.Add(negKey{Name: strings.ToLower(name), Type: qtype, Rcode: rcode}, rrValue[struct{}]{ExpireAt: time.Now().Add(ttl)})
}

// Invalidate all entries for a zone suffix.
func (c *RRCaches[T]) InvalidateZone(zone string) {
	zone = strings.ToLower(zone)
	c.posMu.Lock()
	for _, k := range c.pos.Keys() {
		if strings.HasSuffix(k.Name, zone) {
			c.pos.Remove(k)
		}
	}
	c.posMu.Unlock()
	c.negMu.Lock()
	for _, k := range c.neg.Keys() {
		if strings.HasSuffix(k.Name, zone) {
			c.neg.Remove(k)
		}
	}
	c.negMu.Unlock()
}
