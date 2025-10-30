package dnsserver

import (
	"log/slog"
	"net"
	"strings"
	"time"

	"smart-dns/internal/cache"
	"smart-dns/internal/zone"

	"github.com/miekg/dns"
)

type Resolver struct {
	Logger         *slog.Logger
	Zones          *zone.Store
	Cache          *cache.RRCaches[*dns.Msg]
	EnableResolver bool
	RootServers    []string
}

func NewResolver(l *slog.Logger, zs *zone.Store, c *cache.RRCaches[*dns.Msg]) *Resolver {
	return &Resolver{Logger: l, Zones: zs, Cache: c}
}

func (r *Resolver) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	qname := dns.Fqdn(q.Name)
	qtype := q.Qtype

	// Minimal ANY: avoid dumping whole RRsets. Return SOA only.
	if qtype == dns.TypeANY {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		if zi, _ := r.Zones.GetZoneForName(qname); zi != nil {
			resp.Ns = append(resp.Ns, r.makeSOA(zi))
		}
		_ = w.WriteMsg(resp)
		return
	}

	if v, ok := r.Cache.GetPositive(qname, qtype); ok {
		v.Id = req.Id
		v.RecursionAvailable = false
		_ = w.WriteMsg(v)
		return
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = false

	zi, _ := r.Zones.GetZoneForName(qname)
	if zi == nil {
		if r.EnableResolver {
			if cached, ok := r.Cache.GetPositive(qname, qtype); ok {
				cached.Id = req.Id
				_ = w.WriteMsg(cached)
				return
			}
			if m, ttl := r.iterativeResolve(qname, qtype); m != nil {
				m.Id = req.Id
				_ = w.WriteMsg(m)
				if m.Rcode == dns.RcodeSuccess && (len(m.Answer) > 0 || len(m.Ns) > 0) {
					r.Cache.PutPositive(qname, qtype, m.Copy(), time.Duration(ttl)*time.Second)
				}
				return
			}
		}
		resp.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(resp)
		return
	}

	ans, addl, rcode, ttl := r.lookup(zi, qname, qtype)
	resp.Rcode = rcode
	if len(ans) > 0 {
		resp.Answer = ans
	}
	if len(addl) > 0 {
		resp.Extra = append(resp.Extra, addl...)
	}
	if rcode == dns.RcodeSuccess && len(ans) > 0 {
		r.Cache.PutPositive(qname, qtype, resp.Copy(), time.Duration(ttl)*time.Second)
	} else if rcode != dns.RcodeSuccess {
		negttl := time.Duration(zi.SOA.NegativeTTL) * time.Second
		r.Cache.PutNegative(qname, qtype, rcode, negttl)
		// Attach SOA in authority for negative answers
		resp.Ns = append(resp.Ns, r.makeSOA(zi))
	}
	_ = w.WriteMsg(resp)
}

func (r *Resolver) lookup(zi *zone.ZoneIndex, qname string, qtype uint16) (ans []dns.RR, addl []dns.RR, rcode int, ttl uint32) {
	name := strings.ToLower(dns.Fqdn(qname))
	maxCNAME := 8
	visited := map[string]struct{}{}
	cur := name
	for i := 0; i < maxCNAME; i++ {
		rrset, t, ok := r.findRRSet(zi, cur, qtype)
		if ok {
			ans = append(ans, rrset...)
			// Additional for MX/NS
			addl = append(addl, r.addAdditionals(zi, rrset)...)
			return ans, addl, dns.RcodeSuccess, t
		}
		// Try CNAME at this name
		if _, seen := visited[cur]; seen {
			return nil, nil, dns.RcodeServerFailure, 0
		}
		visited[cur] = struct{}{}
		if rrset, t, ok := r.findRRSet(zi, cur, dns.TypeCNAME); ok {
			ans = append(ans, rrset...)
			// Follow CNAME target
			c := rrset[0].(*dns.CNAME)
			cur = strings.ToLower(c.Target)
			ttl = min(ttl, t)
			if ttl == 0 {
				ttl = t
			}
			continue
		}
		break
	}
	// NX or NODATA
	if r.hasName(zi, name) || r.hasWildcardCandidate(zi, name) {
		return nil, nil, dns.RcodeSuccess, 0 // NODATA; SOA will be attached by caller
	}
	return nil, nil, dns.RcodeNameError, 0
}

func (r *Resolver) findRRSet(zi *zone.ZoneIndex, name string, qtype uint16) (rrs []dns.RR, ttl uint32, ok bool) {
	// Exact name
	if m := zi.ByName[name]; m != nil {
		if rr, ok2 := m[toRRType(qtype)]; ok2 {
			return toRR(name, rr), rr.TTL, true
		}
	}
	// Wildcard: *.closest
	labels := dns.SplitDomainName(name)
	for i := 0; i < len(labels)-1; i++ {
		wc := "*." + strings.Join(labels[i+1:], ".") + "."
		if m := zi.ByName[wc]; m != nil {
			if rr, ok2 := m[toRRType(qtype)]; ok2 {
				return toRR(name, rr), rr.TTL, true
			}
			if rr, ok2 := m[zone.TypeCNAME]; ok2 {
				return toRR(name, rr), rr.TTL, true
			}
		}
	}
	return nil, 0, false
}

func (r *Resolver) hasName(zi *zone.ZoneIndex, name string) bool { _, ok := zi.ByName[name]; return ok }

func (r *Resolver) hasWildcardCandidate(zi *zone.ZoneIndex, name string) bool {
	labels := dns.SplitDomainName(name)
	for i := 0; i < len(labels)-1; i++ {
		wc := "*." + strings.Join(labels[i+1:], ".") + "."
		if _, ok := zi.ByName[wc]; ok {
			return true
		}
	}
	return false
}

func toRRType(qt uint16) zone.RRType {
	switch qt {
	case dns.TypeA:
		return zone.TypeA
	case dns.TypeAAAA:
		return zone.TypeAAAA
	case dns.TypeCNAME:
		return zone.TypeCNAME
	case dns.TypeMX:
		return zone.TypeMX
	case dns.TypeNS:
		return zone.TypeNS
	case dns.TypeTXT:
		return zone.TypeTXT
	case dns.TypeSRV:
		return zone.TypeSRV
	default:
		return zone.RRType("")
	}
}

func toRR(name string, rrset *zone.RRSet) []dns.RR {
	var out []dns.RR
	switch rrset.Type {
	case zone.TypeA:
		for _, ip := range rrset.A {
			r := new(dns.A)
			r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rrset.TTL}
			r.A = ip
			out = append(out, r)
		}
	case zone.TypeAAAA:
		for _, ip := range rrset.AAAA {
			r := new(dns.AAAA)
			r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rrset.TTL}
			r.AAAA = ip
			out = append(out, r)
		}
	case zone.TypeCNAME:
		r := new(dns.CNAME)
		r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: rrset.TTL}
		r.Target = rrset.CNAME
		out = append(out, r)
	case zone.TypeNS:
		for _, ns := range rrset.NS {
			r := new(dns.NS)
			r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rrset.TTL}
			r.Ns = ns
			out = append(out, r)
		}
	case zone.TypeTXT:
		for _, s := range rrset.TXT {
			r := new(dns.TXT)
			r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: rrset.TTL}
			r.Txt = []string{s}
			out = append(out, r)
		}
	case zone.TypeMX:
		for _, mx := range rrset.MX {
			r := new(dns.MX)
			r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: rrset.TTL}
			r.Preference = mx.Preference
			r.Mx = mx.Host
			out = append(out, r)
		}
	case zone.TypeSRV:
		for _, s := range rrset.SRV {
			r := new(dns.SRV)
			r.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: rrset.TTL}
			r.Priority = s.Priority
			r.Weight = s.Weight
			r.Port = s.Port
			r.Target = s.Target
			out = append(out, r)
		}
	}
	return out
}

func (r *Resolver) addAdditionals(zi *zone.ZoneIndex, answers []dns.RR) []dns.RR {
	var extra []dns.RR
	for _, rr := range answers {
		switch x := rr.(type) {
		case *dns.MX:
			extra = append(extra, r.lookupAorAAAA(zi, x.Mx)...)
		case *dns.NS:
			extra = append(extra, r.lookupAorAAAA(zi, x.Ns)...)
		}
	}
	return extra
}

func (r *Resolver) lookupAorAAAA(zi *zone.ZoneIndex, host string) []dns.RR {
	name := strings.ToLower(dns.Fqdn(host))
	var out []dns.RR
	if m := zi.ByName[name]; m != nil {
		if rr, ok := m[zone.TypeA]; ok {
			out = append(out, toRR(name, rr)...)
		}
		if rr, ok := m[zone.TypeAAAA]; ok {
			out = append(out, toRR(name, rr)...)
		}
	}
	return out
}

func (r *Resolver) makeSOA(zi *zone.ZoneIndex) dns.RR {
	soa := new(dns.SOA)
	soa.Hdr = dns.RR_Header{Name: zi.ZoneFQDN, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: zi.TTLDef}
	soa.Ns = zi.SOA.MName
	soa.Mbox = zi.SOA.RName
	soa.Serial = zi.Serial
	soa.Refresh = zi.SOA.Refresh
	soa.Retry = zi.SOA.Retry
	soa.Expire = zi.SOA.Expire
	soa.Minttl = zi.SOA.NegativeTTL
	return soa
}

func min(a, b uint32) uint32 {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

// Iterative resolver using root servers, referrals and glue.
func (r *Resolver) iterativeResolve(qname string, qtype uint16) (*dns.Msg, uint32) {
	if len(r.RootServers) == 0 {
		return nil, 0
	}
	name := dns.Fqdn(qname)
	servers := append([]string(nil), r.RootServers...)
	ttlMin := uint32(0)
	maxDepth := 16
	clientUDP := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	clientTCP := &dns.Client{Net: "tcp", Timeout: 5 * time.Second}

	for depth := 0; depth < maxDepth; depth++ {
		// query current server set
		var resp *dns.Msg
		for _, srv := range servers {
			m := new(dns.Msg)
			m.SetQuestion(name, qtype)
			m.RecursionDesired = false
			r1, _, err := clientUDP.Exchange(m, srv)
			if err != nil {
				continue
			}
			if r1.Truncated {
				r1, _, err = clientTCP.Exchange(m, srv)
				if err != nil {
					continue
				}
			}
			resp = r1
			break
		}
		if resp == nil {
			return nil, 0
		}
		// NXDOMAIN
		if resp.Rcode == dns.RcodeNameError {
			return resp, extractMinTTL(resp)
		}
		// Answer
		if len(resp.Answer) > 0 {
			// If CNAME chain needed
			if qtype != dns.TypeCNAME {
				var hasFinal bool
				for _, rr := range resp.Answer {
					if rr.Header().Rrtype == qtype {
						hasFinal = true
					}
					t := rr.Header().Ttl
					ttlMin = min(ttlMin, t)
				}
				if !hasFinal {
					// follow first CNAME target
					for _, rr := range resp.Answer {
						if c, ok := rr.(*dns.CNAME); ok {
							name = dns.Fqdn(c.Target)
							ttlMin = min(ttlMin, rr.Header().Ttl)
							// keep same servers and continue
							goto next
						}
					}
				}
			} else {
				for _, rr := range resp.Answer {
					ttlMin = min(ttlMin, rr.Header().Ttl)
				}
			}
			return resp, ternaryTTL(ttlMin, 60)
		}
		// Referral: use NS in Authority and glue from Additional
		if len(resp.Ns) > 0 {
			nsNames := make([]string, 0, len(resp.Ns))
			for _, rr := range resp.Ns {
				if rr.Header().Rrtype == dns.TypeNS {
					ns := rr.(*dns.NS).Ns
					nsNames = append(nsNames, ns)
				}
			}
			nextServers := pickGlue(resp, nsNames)
			if len(nextServers) == 0 {
				// try to resolve glue via current servers
				for _, nsn := range nsNames {
					if aips := r.lookupGlueA(clientUDP, clientTCP, servers, nsn); len(aips) > 0 {
						for _, ip := range aips {
							nextServers = append(nextServers, net.JoinHostPort(ip.String(), "53"))
						}
						break
					}
				}
			}
			if len(nextServers) == 0 {
				return nil, 0
			}
			servers = nextServers
			// continue
			goto next
		}
		// NODATA but with SOA in authority -> return
		if len(resp.Ns) > 0 {
			return resp, extractMinTTL(resp)
		}
		return resp, extractMinTTL(resp)
	next:
		continue
	}
	return nil, 0
}

func pickGlue(resp *dns.Msg, nsNames []string) []string {
	glue := []string{}
	set := map[string]struct{}{}
	for _, add := range resp.Extra {
		h := add.Header()
		if h.Rrtype == dns.TypeA {
			a := add.(*dns.A)
			for _, ns := range nsNames {
				if strings.EqualFold(a.Hdr.Name, dns.Fqdn(ns)) {
					glue = append(glue, net.JoinHostPort(a.A.String(), "53"))
					set[a.A.String()] = struct{}{}
				}
			}
		}
		if h.Rrtype == dns.TypeAAAA {
			aaaa := add.(*dns.AAAA)
			for _, ns := range nsNames {
				if strings.EqualFold(aaaa.Hdr.Name, dns.Fqdn(ns)) {
					if _, ok := set[aaaa.AAAA.String()]; !ok {
						glue = append(glue, net.JoinHostPort(aaaa.AAAA.String(), "53"))
					}
				}
			}
		}
	}
	return glue
}

func (r *Resolver) lookupGlueA(cu, ct *dns.Client, servers []string, host string) []net.IP {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = false
	for _, srv := range servers {
		resp, _, err := cu.Exchange(m, srv)
		if err != nil {
			continue
		}
		if resp.Truncated {
			resp, _, err = ct.Exchange(m, srv)
			if err != nil {
				continue
			}
		}
		var ips []net.IP
		for _, a := range resp.Answer {
			if ar, ok := a.(*dns.A); ok {
				ips = append(ips, ar.A)
			}
		}
		if len(ips) > 0 {
			return ips
		}
		// follow referrals quickly by reading extras
		for _, ex := range resp.Extra {
			if ar, ok := ex.(*dns.A); ok {
				return []net.IP{ar.A}
			}
		}
	}
	return nil
}

func extractMinTTL(m *dns.Msg) uint32 {
	ttl := uint32(0)
	for _, s := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range s {
			ttl = min(ttl, rr.Header().Ttl)
		}
	}
	if ttl == 0 {
		ttl = 60
	}
	return ttl
}

func ternaryTTL(v uint32, def uint32) uint32 {
	if v == 0 {
		return def
	}
	return v
}
