# smartdns

An authoritative DNS server written in Go (1.22+) with JSON zone files, negative/positive caching, wildcard and CNAME chain resolution, hot-reload on zone changes, and optional iterative resolver via DNS root servers.

## Highlights
- Authoritative-only by default (no recursion or forwarding). Optional iterative resolver with `--resolver`.
- Listens on UDP and TCP port 53 (configurable).
- RFC 1034/1035 compliant basics: SOA, NS, A, AAAA, CNAME, MX, TXT, SRV. (PTR optional; DNSSEC out of scope.)
- Wildcard records and CNAME chain resolution (max 8 hops; loop protection).
- Negative caching (NXDOMAIN/NODATA) using SOA `negative_ttl` (RFC 2308).
- Minimal responses to `ANY` queries (returns SOA only; avoids large dumps).
- LRUs for positive/negative caches; zone-scoped invalidation on serial bump.
- Hot reload on filesystem changes (fsnotify). Parse errors keep serving the last good zone.
- Additional A/AAAA for MX/NS answers when available.
- Graceful shutdown; simple metrics and health endpoints.

## Architecture (folders)
```
smart-dns/
  cmd/smart-dns/main.go           # CLI entrypoint, flags/env, logging, HTTP health/metrics
  internal/dnsserver/server.go    # UDP/TCP servers, EDNS0-aware, TCP fallback
  internal/dnsserver/handler.go   # ServeDNS logic, wildcard, CNAME chain, additionals, optional resolver
  internal/zone/model.go          # JSON schema structs + validation + in-memory index
  internal/zone/loader.go         # Load/normalize dns/*.dns → ZoneIndex maps
  internal/cache/rrcache.go       # Positive/negative caches with TTL + LRU
  internal/watch/fswatch.go       # fsnotify hot-reload; atomic swap; serial checks
  internal/log/log.go             # slog logger helper
  dns/deneme.com.dns              # example zone
  dns/merhaba.net.dns             # example zone
```

## JSON Zone Format
- File name: `<zone>.dns` under `dns/` directory
- FQDNs may end with a dot; `@` denotes zone apex; relative names are expanded to `<label>.<zone>`.
- `type` is case-insensitive; data is normalized in storage; if `ttl` is missing, `ttl_default` is used.

Example:
```json
{
  "zone": "deneme.com.",
  "serial": 2025103001,
  "ttl_default": 300,
  "soa": {
    "mname": "ns1.deneme.com.",
    "rname": "hostmaster.deneme.com.",
    "refresh": 3600,
    "retry": 600,
    "expire": 604800,
    "negative_ttl": 300
  },
  "ns": ["ns1.deneme.com.", "ns2.deneme.com."],
  "records": [
    { "name": "@",   "type": "A",     "ttl": 300,  "values": ["203.0.113.10"] },
    { "name": "www", "type": "CNAME", "ttl": 300,  "value": "@" },
    { "name": "@",   "type": "MX",    "ttl": 600,  "values": [{"preference":10,"host":"mail.deneme.com."}]},
    { "name": "mail","type": "AAAA",  "ttl": 300,  "values": ["2001:db8::10"] },
    { "name": "_dmarc","type":"TXT",  "ttl": 3600, "values": ["v=DMARC1; p=reject"] },
    { "name": "*",   "type": "A",     "ttl": 60,   "values": ["203.0.113.20"] },
    { "name": "_sip._tcp","type":"SRV","ttl":300,  "values":[{"priority":10,"weight":5,"port":5060,"target":"sip.deneme.com."}]}
  ]
}
```

Validation rules:
- SOA present and at least one NS required; otherwise the zone is rejected.
- CNAME must be the only type on a name (no mixed types).
- Multiple RRs per RRset are supported.

## Installation
Requirements: Go 1.22+

Clone and build:
```bash
git clone https://github.com/alptekinsunnetci/smartdns/smartdns.git
cd smart-dns
go build -trimpath -ldflags "-s -w" -o bin/smart-dns ./cmd/smart-dns
```
Windows (PowerShell):
```powershell
go build -trimpath -ldflags '-s -w' -o bin/smart-dns.exe ./cmd/smart-dns
```

## Running
By default the server is authoritative-only.

```bash
# Linux/macOS (need CAP_NET_BIND_SERVICE or sudo for :53)
./bin/smart-dns \
  --listen-udp=:53 \
  --listen-tcp=:53 \
  --zones-dir=./dns \
  --cache-size=100000 \
  --log-level=info
```

Windows (non-privileged ports example):
```powershell
./bin/smart-dns.exe --listen-udp=:53 --listen-tcp=:53 --zones-dir=./dns
```

Environment variable equivalents:
- `SMARTDNS_LISTEN_UDP`, `SMARTDNS_LISTEN_TCP`, `SMARTDNS_ZONES_DIR`, `SMARTDNS_CACHE_SIZE`, `SMARTDNS_LOG_LEVEL`, `SMARTDNS_METRICS`, `SMARTDNS_HEALTH`.

## Optional Iterative Resolver (via Root Servers)
Authoritative behavior is the default. To resolve names outside your zones iteratively via DNS roots, enable resolver mode:

```bash
./bin/smart-dns --resolver ...
```
- Starts from IANA root servers (IPv4 list embedded), follows NS referrals and glue.
- UDP first, TCP fallback when truncated.
- Depth/time limits to avoid abuse.
- Positive results are cached (respecting TTL); negative responses cached using SOA `negative_ttl`.

## Hot Reloading & Caching
- `dns/*.dns` directory is watched with fsnotify; on file change the JSON is re-parsed.
- If and only if the `serial` increases, the zone is atomically swapped in and all cache entries for that zone are invalidated.
- On parse error the server keeps serving the last valid version and logs a warning.
- Caches:
  - Positive RRset cache key: `(lowercase(qname), qtype)` with TTL expiry.
  - Negative cache key: `(lowercase(qname), qtype, rcode)` with SOA `negative_ttl`.

## Query Examples
```bash
# SOA (authoritative)
dig @127.0.0.1 deneme.com SOA +norecurse

# CNAME → A resolution
# www.deneme.com CNAME @, @ has A; wildcard also supported
dig @127.0.0.1 www.deneme.com A +norecurse

# Wildcard match
dig @127.0.0.1 x.y.deneme.com A +norecurse

# MX with additionals
dig @127.0.0.1 deneme.com MX +noad +norecurse

# Minimal ANY (SOA-only)
dig @127.0.0.1 deneme.com ANY +norecurse
```

## Security & Robustness
- Authoritative-only by default; recursion disabled unless `--resolver` is set.
- CNAME uniqueness enforced at load; malformed zones rejected.
- Depth limits for CNAME chains and iterative resolver; EDNS0-aware; TCP fallback on truncation.
- Concurrency with RWMutex around zone maps and LRU caches; passive TTL eviction on read.
- Graceful shutdown with context and timeouts.

## Performance Notes
- O(1) lookups on in-memory indexes; wildcard resolution via nearest-label search.
- LRU caches to avoid recomputation; additional records added opportunistically.
- UDP payload up to 4096; keep responses minimal for `ANY`.

## Testing (suggested)
- Zone parse/validation (table-driven).
- Cache TTL and negative cache behavior.
- Hot reload with serial increase and cache invalidation.
- Longest suffix zone selection and wildcard resolution.
- CNAME chain limit and loop detection.
- Integration over UDP and TCP using `dns.Client`.

## License
Copyright (c) 2025 Alptekin Sünnetci

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to use,
copy, modify, and distribute the Software for non-commercial purposes only,
subject to the following conditions:

- Commercial use, including selling, licensing, or redistributing for profit,
  is strictly prohibited without the author's written consent.
- The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
