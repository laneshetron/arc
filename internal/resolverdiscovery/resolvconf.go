package resolverdiscovery

import (
	"bufio"
	"io"
	"net/netip"
	"strings"
)

// ParseResolvConf returns the nameserver addresses in an /etc/resolv.conf
// body, in file order.
//
// Only the `nameserver` directive is read. The result is a candidate list,
// not a decision: on systemd hosts the first entry is 127.0.0.53 and Choose
// will refuse it, which is why this function does not filter. Keeping the
// parsing and the policy separate is what lets the policy be tested without
// a host, and lets a caller log why its host was refused (§5.2).
func ParseResolvConf(r io.Reader) ([]netip.Addr, error) {
	var out []netip.Addr
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		// A nameserver line may carry a zone suffix on a link-local
		// address (fe80::1%en0); netip accepts the form and the policy then
		// refuses it, which is the right outcome.
		a, err := netip.ParseAddr(fields[1])
		if err != nil {
			// An unparseable line is skipped rather than fatal: a resolver
			// file with one bad entry still names the working ones.
			continue
		}
		out = append(out, a)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
