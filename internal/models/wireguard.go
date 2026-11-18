package models

import "net/netip"

// WireguardConnection contains provider-generated Wireguard connection data.
type WireguardConnection struct {
	Connection Connection
	PrivateKey string
	Addresses  []netip.Prefix
	Gateway    netip.Addr
}
