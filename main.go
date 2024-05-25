package main

import (
	"net"
)

func main() {

	go startPacketListener(net.ParseIP("127.0.0.1"))

	go startHealthCheckServer()

	select {}
}
