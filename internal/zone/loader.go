package zone

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type Store struct {
	mu    sync.RWMutex
	zones map[string]*ZoneIndex // key: lowercase zone fqdn
}

func NewStore() *Store { return &Store{zones: make(map[string]*ZoneIndex)} }

func (s *Store) GetZoneForName(qname string) (*ZoneIndex, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	name := strings.ToLower(qname)
	best := ""
	var z *ZoneIndex
	for zone := range s.zones {
		if strings.HasSuffix(name, zone) {
			if len(zone) > len(best) {
				best = zone
				z = s.zones[zone]
			}
		}
	}
	return z, best
}

func (s *Store) SwapZone(newz *ZoneIndex) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zones[newz.ZoneFQDN] = newz
}

func (s *Store) RemoveZone(zone string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.zones, strings.ToLower(MustFQDN(zone)))
}

func (s *Store) Snapshot() map[string]*ZoneIndex {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copy := make(map[string]*ZoneIndex, len(s.zones))
	for k, v := range s.zones {
		copy[k] = v
	}
	return copy
}

func LoadZonesDir(dir string) (map[string]*ZoneIndex, error) {
	entries := make([]string, 0, 16)
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".dns") {
			entries = append(entries, path)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.Strings(entries)
	out := make(map[string]*ZoneIndex)
	for _, f := range entries {
		zf, err := readZoneFile(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		zi, err := zf.ToIndex()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out[zi.ZoneFQDN] = zi
	}
	if len(out) == 0 {
		return nil, errors.New("no zones loaded")
	}
	return out, nil
}

func readZoneFile(path string) (*ZoneFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var z ZoneFile
	if err := json.Unmarshal(b, &z); err != nil {
		return nil, err
	}
	return &z, nil
}
