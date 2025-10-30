package dnsserver

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Server struct {
	Logger  *slog.Logger
	UDPAddr string
	TCPAddr string
	Handler dns.Handler

	udpSrv *dns.Server
	tcpSrv *dns.Server
	wg     sync.WaitGroup
}

func NewServer(l *slog.Logger, udp, tcp string, h dns.Handler) *Server {
	return &Server{Logger: l, UDPAddr: udp, TCPAddr: tcp, Handler: h}
}

func (s *Server) Start(ctx context.Context) error {
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		// Respect EDNS0 size
		if o := r.IsEdns0(); o != nil {
			// nothing to do now; miekg/dns manages payload sizes
		}
		s.Handler.ServeDNS(w, r)
	})

	s.udpSrv = &dns.Server{Addr: s.UDPAddr, Net: "udp", UDPSize: 4096}
	s.tcpSrv = &dns.Server{Addr: s.TCPAddr, Net: "tcp"}

	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		if err := s.udpSrv.ListenAndServe(); err != nil {
			s.Logger.Error("udp server", "err", err)
		}
	}()
	go func() {
		defer s.wg.Done()
		if err := s.tcpSrv.ListenAndServe(); err != nil {
			s.Logger.Error("tcp server", "err", err)
		}
	}()

	go func() {
		<-ctx.Done()
		ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.udpSrv.ShutdownContext(ctx2)
		_ = s.tcpSrv.ShutdownContext(ctx2)
	}()
	return nil
}

func (s *Server) AddrUDP() (net.Addr, bool) {
	if s.udpSrv != nil && s.udpSrv.Listener != nil {
		return s.udpSrv.Listener.Addr(), true
	}
	return nil, false
}
func (s *Server) AddrTCP() (net.Addr, bool) {
	if s.tcpSrv != nil && s.tcpSrv.Listener != nil {
		return s.tcpSrv.Listener.Addr(), true
	}
	return nil, false
}

func (s *Server) Wait() { s.wg.Wait() }
