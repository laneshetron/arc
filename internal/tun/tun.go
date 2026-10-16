// Package tun wraps the platform TUN device (via wireguard-go's tun
// package) with batch-friendly buffers, and configures addresses and routes
// (spec §17).
package tun

import (
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// Offset is the headroom reserved before each packet in read and write
// buffers. Linux needs room for a virtio-net header when offloads are on;
// other platforms need a 4-byte protocol header.
const Offset = 16

// bufCap leaves room for the device to coalesce packets in place on write
// (GRO) and to deliver GSO segments on read.
const bufCap = Offset + 65535

// Device is a TUN interface. Read and Write may run on different
// goroutines, but each must be used by only one goroutine at a time.
type Device struct {
	dev  wgtun.Device
	name string
	dns  dnsState

	rbufs  [][]byte
	rsizes []int
	wbufs  [][]byte
}

// Create opens a TUN device. The interface stays down until configured.
func Create(name string, mtu int) (*Device, error) {
	dev, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, err
	}
	actual, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, err
	}
	n := dev.BatchSize()
	d := &Device{dev: dev, name: actual, rsizes: make([]int, n)}
	for range n {
		d.rbufs = append(d.rbufs, make([]byte, bufCap))
		d.wbufs = append(d.wbufs, make([]byte, 0, bufCap))
	}
	return d, nil
}

func (d *Device) Name() string { return d.name }

// Read blocks until packets arrive and returns them. The slices are valid
// only until the next Read.
func (d *Device) Read() ([][]byte, error) {
	n, err := d.dev.Read(d.rbufs, d.rsizes, Offset)
	out := make([][]byte, n)
	for i := range n {
		out[i] = d.rbufs[i][Offset : Offset+d.rsizes[i]]
	}
	return out, err
}

// Write sends packets to the kernel, in batches the device supports.
func (d *Device) Write(pkts [][]byte) error {
	for len(pkts) > 0 {
		k := min(len(pkts), len(d.wbufs))
		bufs := d.wbufs[:k]
		for i, p := range pkts[:k] {
			bufs[i] = append(bufs[i][:Offset], p...)
		}
		if _, err := d.dev.Write(bufs, Offset); err != nil {
			return err
		}
		pkts = pkts[k:]
	}
	return nil
}

func (d *Device) Close() error { return d.dev.Close() }
