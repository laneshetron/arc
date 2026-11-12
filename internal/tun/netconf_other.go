//go:build !linux && !darwin

package tun

import (
	"errors"
	"net/netip"
)

var errUnsupported = errors.New("tun: interface configuration is only implemented on Linux")

func (d *Device) Configure(netip.Prefix, int) error             { return errUnsupported }
func (d *Device) AddRoute(netip.Prefix) error                   { return errUnsupported }
func (d *Device) FullTunnel(uint32, int) (func() error, error)  { return nil, errUnsupported }
func (d *Device) ConfigureDNS(netip.Addr) (func() error, error) { return nil, errUnsupported }

const (
	DefaultName   = "arc0"
	DNSManager    = "none"
	PolicyRouting = false
)

func Underlay() (string, error) { return "", errUnsupported }
