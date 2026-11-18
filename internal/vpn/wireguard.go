package vpn

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/gluetun/internal/provider"
	"github.com/qdm12/gluetun/internal/wireguard"
	"github.com/qdm12/gosettings"
)

// setupWireguard sets Wireguard up using the configurators and settings given.
// It returns the selected connection, an optional provider-generated gateway
// for port forwarding, and an error if setup fails.
func setupWireguard(ctx context.Context, netlinker NetLinker,
	fw Firewall, providerConf provider.Provider, restrictedClient provider.RestrictedClient,
	settings settings.VPN, ipv6SupportLevel netlink.IPv6SupportLevel, logger wireguard.Logger) (
	wireguarder *wireguard.Wireguard, connection models.Connection,
	gateway netip.Addr, err error,
) {
	ipv6Internet := ipv6SupportLevel == netlink.IPv6Internet
	dynamicProvider, dynamic := providerConf.(provider.DynamicWireguardProvider)
	if dynamic {
		connection, err = dynamicProvider.GetAPIWireguardConnection(ctx,
			settings.Provider.ServerSelection, restrictedClient)
	} else {
		connection, err = providerConf.GetConnection(settings.Provider.ServerSelection, ipv6Internet)
	}
	if err != nil {
		return nil, models.Connection{}, netip.Addr{}, fmt.Errorf("finding a VPN server: %w", err)
	}

	var wireguardSettings wireguard.Settings
	if dynamic {
		wireguardSettings, connection, gateway, err = registeredWireguardSettings(ctx,
			dynamicProvider, connection, settings, restrictedClient)
		if err != nil {
			return nil, models.Connection{}, netip.Addr{}, err
		}
	} else {
		wireguardSettings = buildWireguardSettings(connection,
			settings.Wireguard, ipv6SupportLevel.IsSupported())
	}

	logger.Debug("Wireguard server public key: " + wireguardSettings.PublicKey)
	logger.Debug("Wireguard client private key: " + gosettings.ObfuscateKey(wireguardSettings.PrivateKey))
	logger.Debug("Wireguard pre-shared key: " + gosettings.ObfuscateKey(wireguardSettings.PreSharedKey))

	wireguarder, err = wireguard.New(wireguardSettings, netlinker, logger)
	if err != nil {
		return nil, models.Connection{}, netip.Addr{}, fmt.Errorf("creating Wireguard: %w", err)
	}

	err = fw.SetVPNConnection(ctx, connection, settings.Wireguard.Interface)
	if err != nil {
		return nil, models.Connection{}, netip.Addr{}, fmt.Errorf("setting firewall: %w", err)
	}

	return wireguarder, connection, gateway, nil
}

func registeredWireguardSettings(ctx context.Context,
	dynamicProvider provider.DynamicWireguardProvider,
	connection models.Connection, settings settings.VPN,
	restrictedClient provider.RestrictedClient,
) (wireguardSettings wireguard.Settings, updatedConnection models.Connection,
	gateway netip.Addr, err error,
) {
	wireguardConnection, err := dynamicProvider.RegisterWireguard(ctx, connection,
		*settings.OpenVPN.User, *settings.OpenVPN.Password, restrictedClient)
	if err != nil {
		return wireguard.Settings{}, models.Connection{}, netip.Addr{},
			fmt.Errorf("registering Wireguard connection: %w", err)
	}
	wireguardSettings = buildRegisteredWireguardSettings(wireguardConnection,
		settings.Wireguard)
	return wireguardSettings, wireguardConnection.Connection, wireguardConnection.Gateway, nil
}

func buildRegisteredWireguardSettings(registration models.WireguardConnection,
	userSettings settings.Wireguard,
) wireguard.Settings {
	privateKey := registration.PrivateKey
	userSettings.PrivateKey = &privateKey
	userSettings.Addresses = append([]netip.Prefix(nil), registration.Addresses...)
	if *userSettings.PersistentKeepaliveInterval == 0 {
		const piaPersistentKeepalive = 25 * time.Second
		userSettings.PersistentKeepaliveInterval = new(piaPersistentKeepalive)
	}
	const piaIPv6Supported = false
	return buildWireguardSettings(registration.Connection, userSettings, piaIPv6Supported)
}

func buildWireguardSettings(connection models.Connection,
	userSettings settings.Wireguard, ipv6Supported bool,
) (settings wireguard.Settings) {
	settings.PrivateKey = *userSettings.PrivateKey
	settings.PublicKey = connection.PubKey
	settings.PreSharedKey = *userSettings.PreSharedKey
	settings.InterfaceName = userSettings.Interface
	settings.Implementation = userSettings.Implementation
	if *userSettings.MTU > 0 {
		settings.MTU = *userSettings.MTU
	} else {
		// The default is 1320 which is NOT the wireguard-go default
		// of 1420 because this impacts bandwidth a lot on some
		// VPN providers, see https://github.com/qdm12/gluetun/issues/1650.
		// It has been lowered to 1320 following quite a bit of
		// investigation in the issue: https://github.com/qdm12/gluetun/issues/2533.
		const defaultMTU = 1320
		settings.MTU = defaultMTU
	}
	settings.IPv6 = &ipv6Supported

	const rulePriority = 101 // 100 is to receive external connections
	settings.RulePriority = rulePriority

	settings.Endpoint = netip.AddrPortFrom(connection.IP, connection.Port)

	settings.Addresses = make([]netip.Prefix, 0, len(userSettings.Addresses))
	for _, address := range userSettings.Addresses {
		if !ipv6Supported && address.Addr().Is6() {
			continue
		}
		addressCopy := netip.PrefixFrom(address.Addr(), address.Bits())
		settings.Addresses = append(settings.Addresses, addressCopy)
	}

	settings.AllowedIPs = make([]netip.Prefix, 0, len(userSettings.AllowedIPs))
	for _, allowedIP := range userSettings.AllowedIPs {
		if !ipv6Supported && allowedIP.Addr().Is6() {
			continue
		}
		settings.AllowedIPs = append(settings.AllowedIPs, allowedIP)
	}

	settings.PersistentKeepaliveInterval = *userSettings.PersistentKeepaliveInterval
	gso := *userSettings.GSO
	settings.GSO = &gso

	return settings
}
