package watch

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

type ZoneReloader interface {
	OnZoneUpdated(path string)
	OnZoneRemoved(zone string)
}

func WatchDir(ctx context.Context, dir string, r ZoneReloader) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()
	if err := w.Add(dir); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-w.Events:
			name := strings.ToLower(ev.Name)
			if !strings.HasSuffix(name, ".dns") {
				continue
			}
			// Debounce brief burst
			time.AfterFunc(100*time.Millisecond, func() {
				if ev.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
					// zone name equals filename without dir
					base := filepath.Base(name)
					zone := strings.TrimSuffix(base, filepath.Ext(base))
					r.OnZoneRemoved(zone)
					return
				}
				r.OnZoneUpdated(name)
			})
		case <-w.Errors:
			// ignore
		}
	}
}
