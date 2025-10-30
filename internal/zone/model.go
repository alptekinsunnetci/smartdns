package zone

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// Normalized to lowercase internally; external wire preserves qname case.

type ZoneFile struct {
	Zone       string      `json:"zone"`
	Serial     uint32      `json:"serial"`
	TTLDefault uint32      `json:"ttl_default"`
	SOA        SOA         `json:"soa"`
	NS         []string    `json:"ns"`
	Records    []RawRecord `json:"records"`
}

type SOA struct {
	MName       string `json:"mname"`
	RName       string `json:"rname"`
	Refresh     uint32 `json:"refresh"`
	Retry       uint32 `json:"retry"`
	Expire      uint32 `json:"expire"`
	NegativeTTL uint32 `json:"negative_ttl"`
}

type RawRecord struct {
	Name   string  `json:"name"`
	Type   string  `json:"type"`
	TTL    *uint32 `json:"ttl"`
	Value  string  `json:"value"`  // for CNAME only
	Values any     `json:"values"` // []string or []struct depending on type
}

// Indexed zone in memory.
type RRType string

const (
	TypeA     RRType = "A"
	TypeAAAA  RRType = "AAAA"
	TypeCNAME RRType = "CNAME"
	TypeMX    RRType = "MX"
	TypeNS    RRType = "NS"
	TypeTXT   RRType = "TXT"
	TypeSRV   RRType = "SRV"
)

type RRSet struct {
	Type RRType
	TTL  uint32
	// Canonical RDATA kept as strings or concrete structs for MX/SRV.
	A     []net.IP
	AAAA  []net.IP
	CNAME string // FQDN
	NS    []string
	TXT   []string
	MX    []MX
	SRV   []SRV
}

type MX struct {
	Preference uint16 `json:"preference"`
	Host       string `json:"host"`
}

type SRV struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
}

type ZoneIndex struct {
	ZoneFQDN string
	Serial   uint32
	SOA      SOA
	TTLDef   uint32
	// name(lowercase FQDN) -> type -> RRSet
	ByName map[string]map[RRType]*RRSet
}

func (z *ZoneFile) Validate() error {
	if z == nil {
		return errors.New("nil zone")
	}
	if z.Zone == "" {
		return errors.New("zone is required")
	}
	if !strings.HasSuffix(z.Zone, ".") {
		z.Zone += "."
	}
	if z.SOA.MName == "" || z.SOA.RName == "" {
		return errors.New("soa.mname and soa.rname required")
	}
	if len(z.NS) == 0 {
		return errors.New("at least one NS required")
	}
	return nil
}

func NormalizeFQDN(name string, zone string) string {
	if name == "@" || name == "" {
		return strings.ToLower(zone)
	}
	if strings.HasSuffix(name, ".") {
		return strings.ToLower(name)
	}
	return strings.ToLower(name + "." + zone)
}

func MustFQDN(name string) string {
	if name == "" {
		return name
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

func ensureTTL(ttl *uint32, def uint32) uint32 {
	if ttl == nil || *ttl == 0 {
		return def
	}
	return *ttl
}

func (z *ZoneFile) ToIndex() (*ZoneIndex, error) {
	if err := z.Validate(); err != nil {
		return nil, err
	}
	zoneFQDN := MustFQDN(z.Zone)
	idx := &ZoneIndex{
		ZoneFQDN: strings.ToLower(zoneFQDN),
		Serial:   z.Serial,
		SOA:      z.SOA,
		TTLDef:   z.TTLDefault,
		ByName:   make(map[string]map[RRType]*RRSet),
	}

	// Add NS at apex as RRSet
	if len(z.NS) > 0 {
		name := strings.ToLower(zoneFQDN)
		m := ensureName(idx.ByName, name)
		m[TypeNS] = &RRSet{Type: TypeNS, TTL: ttlOrDef(nil, z.TTLDefault), NS: normalizeFQDNs(z.NS)}
	}

	// Iterate records
	for _, r := range z.Records {
		rt := RRType(strings.ToUpper(r.Type))
		fqdn := NormalizeFQDN(r.Name, zoneFQDN)
		m := ensureName(idx.ByName, fqdn)
		ttl := ensureTTL(r.TTL, z.TTLDefault)
		switch rt {
		case TypeCNAME:
			if r.Value == "" {
				return nil, fmt.Errorf("CNAME requires value for %s", fqdn)
			}
			if hasOtherTypes(m) {
				return nil, fmt.Errorf("CNAME must be unique at name %s", fqdn)
			}
			m[TypeCNAME] = &RRSet{Type: TypeCNAME, TTL: ttl, CNAME: NormalizeFQDN(r.Value, zoneFQDN)}
		case TypeA:
			ips, err := toStringSlice(r.Values)
			if err != nil {
				return nil, err
			}
			var list []net.IP
			for _, s := range ips {
				ip := net.ParseIP(s)
				if ip == nil || ip.To4() == nil {
					return nil, fmt.Errorf("invalid A ip %s", s)
				}
				list = append(list, ip.To4())
			}
			appendRRSet(m, TypeA, ttl).A = append(appendRRSet(m, TypeA, ttl).A, list...)
		case TypeAAAA:
			ips, err := toStringSlice(r.Values)
			if err != nil {
				return nil, err
			}
			var list []net.IP
			for _, s := range ips {
				ip := net.ParseIP(s)
				if ip == nil || ip.To16() == nil || ip.To4() != nil {
					return nil, fmt.Errorf("invalid AAAA ip %s", s)
				}
				list = append(list, ip)
			}
			appendRRSet(m, TypeAAAA, ttl).AAAA = append(appendRRSet(m, TypeAAAA, ttl).AAAA, list...)
		case TypeTXT:
			vals, err := toStringSlice(r.Values)
			if err != nil {
				return nil, err
			}
			appendRRSet(m, TypeTXT, ttl).TXT = append(appendRRSet(m, TypeTXT, ttl).TXT, vals...)
		case TypeNS:
			vals, err := toStringSlice(r.Values)
			if err != nil {
				return nil, err
			}
			appendRRSet(m, TypeNS, ttl).NS = append(appendRRSet(m, TypeNS, ttl).NS, normalizeFQDNs(vals)...)
		case TypeMX:
			mxs, err := toMXSlice(r.Values)
			if err != nil {
				return nil, err
			}
			for i := range mxs {
				mxs[i].Host = strings.ToLower(MustFQDN(mxs[i].Host))
			}
			appendRRSet(m, TypeMX, ttl).MX = append(appendRRSet(m, TypeMX, ttl).MX, mxs...)
		case TypeSRV:
			srvs, err := toSRVSlice(r.Values)
			if err != nil {
				return nil, err
			}
			for i := range srvs {
				srvs[i].Target = strings.ToLower(MustFQDN(srvs[i].Target))
			}
			appendRRSet(m, TypeSRV, ttl).SRV = append(appendRRSet(m, TypeSRV, ttl).SRV, srvs...)
		default:
			return nil, fmt.Errorf("unsupported type: %s", r.Type)
		}
	}

	return idx, nil
}

func ensureName(by map[string]map[RRType]*RRSet, name string) map[RRType]*RRSet {
	if by[name] == nil {
		by[name] = make(map[RRType]*RRSet)
	}
	return by[name]
}

func appendRRSet(m map[RRType]*RRSet, t RRType, ttl uint32) *RRSet {
	if m[t] == nil {
		m[t] = &RRSet{Type: t, TTL: ttl}
	}
	if m[t].TTL > ttl {
		m[t].TTL = ttl
	}
	return m[t]
}

func normalizeFQDNs(v []string) []string {
	out := make([]string, 0, len(v))
	for _, s := range v {
		out = append(out, strings.ToLower(MustFQDN(s)))
	}
	return out
}

func ttlOrDef(ttl *uint32, def uint32) uint32 { return ensureTTL(ttl, def) }

func hasOtherTypes(m map[RRType]*RRSet) bool {
	if len(m) == 0 {
		return false
	}
	if len(m) == 1 {
		_, ok := m[TypeCNAME]
		return ok
	}
	return true
}

func toStringSlice(v any) ([]string, error) {
	switch x := v.(type) {
	case []any:
		res := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, errors.New("expected string in values")
			}
			res = append(res, s)
		}
		return res, nil
	case nil:
		return nil, errors.New("values missing")
	default:
		return nil, errors.New("invalid values type")
	}
}

func toMXSlice(v any) ([]MX, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, errors.New("values must be array for MX")
	}
	out := make([]MX, 0, len(arr))
	for _, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, errors.New("MX value must be object")
		}
		prefF, ok1 := m["preference"].(float64)
		hostS, ok2 := m["host"].(string)
		if !ok1 || !ok2 {
			return nil, errors.New("MX requires preference and host")
		}
		out = append(out, MX{Preference: uint16(prefF), Host: hostS})
	}
	return out, nil
}

func toSRVSlice(v any) ([]SRV, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, errors.New("values must be array for SRV")
	}
	out := make([]SRV, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(map[string]any)
		if !ok {
			return nil, errors.New("SRV value must be object")
		}
		prio, ok1 := s["priority"].(float64)
		w, ok2 := s["weight"].(float64)
		p, ok3 := s["port"].(float64)
		target, ok4 := s["target"].(string)
		if !ok1 || !ok2 || !ok3 || !ok4 {
			return nil, errors.New("SRV requires priority, weight, port, target")
		}
		out = append(out, SRV{Priority: uint16(prio), Weight: uint16(w), Port: uint16(p), Target: target})
	}
	return out, nil
}
