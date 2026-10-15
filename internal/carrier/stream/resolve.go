package stream

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
)

// ResolveEndpoints bootstraps the relay before full-tunnel DNS/routing
// changes. Callers retain the original hostname for TLS verification.
// The returned address set lasts for this client process; restart to
// refresh it after an operator changes the relay's DNS records.
func ResolveEndpoints(ctx context.Context, endpoint string) ([]netip.AddrPort, error) {
	return resolveEndpoints(ctx, endpoint, net.DefaultResolver.LookupNetIP)
}

func resolveEndpoints(ctx context.Context, endpoint string, lookup func(context.Context, string, string) ([]netip.Addr, error)) ([]netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return nil, errors.New("stream: endpoint requires a numeric nonzero port")
	}
	ips := []netip.Addr{}
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = append(ips, ip)
	} else {
		ips, err = lookup(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	out := make([]netip.AddrPort, 0, len(ips))
	for _, ip := range ips {
		if ip.IsValid() {
			out = append(out, netip.AddrPortFrom(ip.Unmap(), uint16(n)))
		}
	}
	if len(out) == 0 {
		return nil, errors.New("stream: relay DNS returned no usable addresses")
	}
	return out, nil
}
