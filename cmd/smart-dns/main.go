package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"smart-dns/internal/cache"
	"smart-dns/internal/dnsserver"
	logx "smart-dns/internal/log"
	"smart-dns/internal/watch"
	"smart-dns/internal/zone"

	"github.com/miekg/dns"
)

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	var listenUDP = flag.String("listen-udp", getenv("SMARTDNS_LISTEN_UDP", ":53"), "UDP listen addr")
	var listenTCP = flag.String("listen-tcp", getenv("SMARTDNS_LISTEN_TCP", ":53"), "TCP listen addr")
	var zonesDir = flag.String("zones-dir", getenv("SMARTDNS_ZONES_DIR", "./dns"), "zones dir")
	var cacheSize = flag.Int("cache-size", atoi(getenv("SMARTDNS_CACHE_SIZE", "100000"), 100000), "RR cache size")
	var logLevel = flag.String("log-level", getenv("SMARTDNS_LOG_LEVEL", "info"), "log level")
	var metricsAddr = flag.String("metrics", getenv("SMARTDNS_METRICS", ":9090"), "metrics addr")
	var healthAddr = flag.String("health", getenv("SMARTDNS_HEALTH", ":8080"), "health addr")
	var enableResolver = flag.Bool("resolver", false, "enable iterative resolver via root servers")
	flag.Parse()

	logger := logx.New(*logLevel)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	zonesMap, err := zone.LoadZonesDir(*zonesDir)
	if err != nil {
		logger.Error("load zones", "err", err)
		os.Exit(1)
	}
	store := zone.NewStore()
	for _, zi := range zonesMap {
		store.SwapZone(zi)
	}

	rrcache, err := cache.NewRRCaches[*dns.Msg](*cacheSize)
	if err != nil {
		logger.Error("cache init", "err", err)
		os.Exit(1)
	}

	res := dnsserver.NewResolver(logger, store, rrcache)
	if *enableResolver {
		res.EnableResolver = true
		res.RootServers = defaultRootServers()
	}
	srv := dnsserver.NewServer(logger, *listenUDP, *listenTCP, res)
	if err := srv.Start(ctx); err != nil {
		logger.Error("server start", "err", err)
		os.Exit(1)
	}

	// HTTP: health and metrics
	var reqCount atomic.Int64
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); _, _ = w.Write([]byte("ok")) })
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprintf(w, "smartdns_requests_total %d\n", reqCount.Load())
	})
	go func() { _ = http.ListenAndServe(*healthAddr, nil) }()
	if *metricsAddr != *healthAddr {
		go func() { _ = http.ListenAndServe(*metricsAddr, nil) }()
	}

	// Watch zones dir
	go func() {
		_ = watch.WatchDir(ctx, *zonesDir, &zoneReloader{logger: logger, store: store, cache: rrcache})
	}()

	logger.Info("smart-dns started", "udp", *listenUDP, "tcp", *listenTCP, "zones", strings.Join(mkKeys(zonesMap), ","))
	<-ctx.Done()
	logger.Info("shutting down")
	time.Sleep(200 * time.Millisecond)
}

type zoneReloader struct {
	logger *slog.Logger
	store  *zone.Store
	cache  *cache.RRCaches[*dns.Msg]
}

func (z *zoneReloader) OnZoneUpdated(path string) {
	zf, err := readZonePath(path)
	if err != nil {
		z.logger.Warn("zone parse", "path", path, "err", err)
		return
	}
	zi, err := zf.ToIndex()
	if err != nil {
		z.logger.Warn("zone index", "path", path, "err", err)
		return
	}
	old, _ := z.store.GetZoneForName(zi.ZoneFQDN)
	if old != nil && zi.Serial <= old.Serial {
		return
	}
	z.store.SwapZone(zi)
	z.cache.InvalidateZone(zi.ZoneFQDN)
	z.logger.Info("zone reloaded", "zone", zi.ZoneFQDN, "serial", zi.Serial)
}

func (z *zoneReloader) OnZoneRemoved(zoneName string) {
	z.store.RemoveZone(zoneName + ".")
	z.cache.InvalidateZone(zoneName + ".")
	z.logger.Info("zone removed", "zone", zoneName)
}

func mkKeys(m map[string]*zone.ZoneIndex) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func atoi(s string, def int) int {
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

// small local helper to read JSON path without exporting loader internals here
func readZonePath(path string) (*zone.ZoneFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var zf zone.ZoneFile
	if err := json.Unmarshal(b, &zf); err != nil {
		return nil, err
	}
	return &zf, nil
}

func defaultRootServers() []string {
	// IANA root servers (A-M) IPv4 only for brevity; can be extended with IPv6.
	roots := []string{
		"198.41.0.4:53",     // a.root-servers.net
		"199.9.14.201:53",   // b.root-servers.net
		"192.33.4.12:53",    // c.root-servers.net
		"199.7.91.13:53",    // d.root-servers.net
		"192.203.230.10:53", // e.root-servers.net
		"192.5.5.241:53",    // f.root-servers.net
		"192.112.36.4:53",   // g.root-servers.net
		"198.97.190.53:53",  // h.root-servers.net
		"192.36.148.17:53",  // i.root-servers.net
		"192.58.128.30:53",  // j.root-servers.net
		"193.0.14.129:53",   // k.root-servers.net
		"199.7.83.42:53",    // l.root-servers.net
		"202.12.27.33:53",   // m.root-servers.net
	}
	return roots
}
