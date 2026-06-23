//go:build !linux

package server

import "fmt"

func openPacketDevice(config normalizedExitConfig) (packetDevice, error) {
	return nil, fmt.Errorf("exit mode requires Linux TUN support")
}
