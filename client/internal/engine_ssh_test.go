package internal

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	firewallManager "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	sshserver "github.com/netbirdio/netbird/client/ssh/server"
)

type dnatRule struct {
	addr           netip.Addr
	protocol       firewallManager.Protocol
	originalPort   uint16
	translatedPort uint16
}

// dnatRecorder keeps the inbound DNAT rules the engine has installed. Every
// other firewall method panics through the nil embedded interface, which flags
// an unexpected call.
type dnatRecorder struct {
	firewallManager.Manager
	rules map[dnatRule]struct{}
}

func newDNATRecorder() *dnatRecorder {
	return &dnatRecorder{rules: map[dnatRule]struct{}{}}
}

func (r *dnatRecorder) AddInboundDNAT(addr netip.Addr, protocol firewallManager.Protocol, originalPort, translatedPort uint16) error {
	r.rules[dnatRule{addr, protocol, originalPort, translatedPort}] = struct{}{}
	return nil
}

func (r *dnatRecorder) RemoveInboundDNAT(addr netip.Addr, protocol firewallManager.Protocol, originalPort, translatedPort uint16) error {
	delete(r.rules, dnatRule{addr, protocol, originalPort, translatedPort})
	return nil
}

func TestSSHPortRedirection(t *testing.T) {
	v4 := netip.MustParseAddr("100.64.0.1")
	v6 := netip.MustParseAddr("fd00:4e42::1")

	tests := []struct {
		name      string
		port      uint16
		wantRules []dnatRule
	}{
		{
			name: "default port 22 redirects to the internal port",
			port: 22,
			wantRules: []dnatRule{
				{v4, firewallManager.ProtocolTCP, 22, sshserver.InternalSSHPort},
				{v6, firewallManager.ProtocolTCP, 22, sshserver.InternalSSHPort},
			},
		},
		{
			// The host's own sshd keeps port 22 on the NetBird address.
			name: "custom port leaves 22 alone",
			port: 22000,
			wantRules: []dnatRule{
				{v4, firewallManager.ProtocolTCP, 22000, sshserver.InternalSSHPort},
				{v6, firewallManager.ProtocolTCP, 22000, sshserver.InternalSSHPort},
			},
		},
		{
			name: "zero installs no redirect",
			port: 0,
		},
		{
			// Redirecting the listen port to itself would be a no-op rule.
			name: "the internal port itself installs no redirect",
			port: sshserver.InternalSSHPort,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := newDNATRecorder()
			e := &Engine{
				config:   &EngineConfig{ServerSSHRedirectPort: tt.port},
				firewall: fw,
				wgInterface: &MockWGIface{
					AddressFunc: func() wgaddr.Address {
						return wgaddr.Address{IP: v4, IPv6: v6}
					},
				},
			}

			require.NoError(t, e.setupSSHPortRedirection())

			got := make([]dnatRule, 0, len(fw.rules))
			for r := range fw.rules {
				got = append(got, r)
			}
			assert.ElementsMatch(t, tt.wantRules, got, "installed DNAT rules")

			require.NoError(t, e.cleanupSSHPortRedirection())
			assert.Empty(t, fw.rules, "cleanup must remove every rule setup installed")
		})
	}
}

func TestSSHPortRedirectionSkipsV6WithoutAddress(t *testing.T) {
	v4 := netip.MustParseAddr("100.64.0.1")
	fw := newDNATRecorder()
	e := &Engine{
		config:   &EngineConfig{ServerSSHRedirectPort: 22000},
		firewall: fw,
		wgInterface: &MockWGIface{
			AddressFunc: func() wgaddr.Address { return wgaddr.Address{IP: v4} },
		},
	}

	require.NoError(t, e.setupSSHPortRedirection())

	_, ok := fw.rules[dnatRule{v4, firewallManager.ProtocolTCP, 22000, sshserver.InternalSSHPort}]
	assert.True(t, ok, "v4 redirect must be installed")
	assert.Len(t, fw.rules, 1, "no v6 rule without a v6 address")
}
