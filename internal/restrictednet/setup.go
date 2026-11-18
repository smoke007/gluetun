package restrictednet

import (
	"errors"
	"fmt"

	"github.com/qdm12/dns/v2/pkg/provider"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/gluetun/internal/routing"
)

// Setup creates a restricted network client, used to register with the VPN
// provider API before the tunnel is up. It uses the interface of the IPv4
// default route found in defaultRoutes, and resolves the upstream DNS
// provider names given into resolver instances.
func Setup(defaultRoutes []routing.DefaultRoute,
	upstreamDNSProviderNames []string, firewall Firewall, ipv6Supported bool,
) (restrictedClient *Client, err error) {
	defaultIPv4Interface := ""
	for _, defaultRoute := range defaultRoutes {
		if defaultRoute.Family == netlink.FamilyV4 {
			defaultIPv4Interface = defaultRoute.NetInterface
			break
		}
	}
	if defaultIPv4Interface == "" {
		return nil, errors.New("IPv4 default interface is not found")
	}

	availableDNSProviders := provider.NewProviders()
	upstreamResolvers := make([]provider.Provider, len(upstreamDNSProviderNames))
	for i, providerName := range upstreamDNSProviderNames {
		upstreamResolver, err := availableDNSProviders.Get(providerName)
		if err != nil {
			return nil, fmt.Errorf("DNS provider %q: %w", providerName, err)
		}
		upstreamResolvers[i] = upstreamResolver
	}

	return New(Settings{
		DefaultInterface:  defaultIPv4Interface,
		IPv6Supported:     &ipv6Supported,
		Firewall:          firewall,
		UpstreamResolvers: upstreamResolvers,
	}), nil
}
