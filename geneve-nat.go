package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	DefaultGenevePort = 6081
	InterfaceName     = "eth0"
	MaxPacketSize     = 1600
	MinPort           = 1024
	MaxPort           = 65535
)

type connKey struct {
	srcIP   string
	srcPort uint16
	dstIP   string
	dstPort uint16
}

type connValue struct {
	conn net.Conn
	udp  *net.UDPConn
}

var (
	connMappings = sync.Map{}
	portMappings = sync.Map{}
	randPorts    = generateRandomPorts()
	portMutex    = &sync.Mutex{}
	packetPool   = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, MaxPacketSize)
			return &buf
		},
	}
)

func generateRandomPorts() []int {
	ports := make([]int, MaxPort-MinPort)
	for i := range ports {
		ports[i] = rand.Intn(MaxPort-MinPort) + MinPort
	}
	return ports
}

func startPacketListener(eip net.IP) {
	handle, err := pcap.OpenLive(InterfaceName, MaxPacketSize, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening pcap handle: %v", err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(fmt.Sprintf("udp and port %d", DefaultGenevePort)); err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		go handlePacket(packet, &eip)
	}
}

func handlePacket(packet gopacket.Packet, eip *net.IP) {
	geneveLayer := packet.Layer(layers.LayerTypeGeneve)
	if geneveLayer == nil {
		return
	}

	geneve, _ := geneveLayer.(*layers.Geneve)
	payload := geneve.Payload

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)

	originalKey := connKey{srcIP: ip.SrcIP.String(), srcPort: 0, dstIP: ip.DstIP.String(), dstPort: 0}
	newSrcIP := *eip
	natKey := connKey{srcIP: newSrcIP.String(), srcPort: 0, dstIP: ip.DstIP.String(), dstPort: 0}

	connMappings.Store(originalKey, natKey)
	connMappings.Store(natKey, originalKey)

	ip.SrcIP = newSrcIP

	switch ip.Protocol {
	case layers.IPProtocolUDP:
		handlePacketCommon(ip, payload, eip, layers.LayerTypeUDP)
	case layers.IPProtocolTCP:
		handlePacketCommon(ip, payload, eip, layers.LayerTypeTCP)
	case layers.IPProtocolICMPv4:
		handlePacketCommon(ip, payload, eip, layers.LayerTypeICMPv4)
	default:
		log.Printf("Unhandled protocol: %v", ip.Protocol)
	}
}

func handlePacketCommon(ip *layers.IPv4, payload []byte, eip *net.IP, layerType gopacket.LayerType) {
	packet := gopacket.NewPacket(payload, layerType, gopacket.Default)
	var layer gopacket.Layer

	switch layerType {
	case layers.LayerTypeUDP:
		layer = packet.Layer(layers.LayerTypeUDP)
	case layers.LayerTypeTCP:
		layer = packet.Layer(layers.LayerTypeTCP)
	case layers.LayerTypeICMPv4:
		layer = packet.Layer(layers.LayerTypeICMPv4)
	}

	if layer == nil {
		return
	}

	var dstPort uint16
	var bufferErr error

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	switch layerType {
	case layers.LayerTypeUDP:
		udp := layer.(*layers.UDP)
		dstPort = uint16(udp.DstPort)
		bufferErr = gopacket.SerializeLayers(buffer, opts, ip, udp, gopacket.Payload(udp.Payload))
		go sendUDPPacket(buffer.Bytes(), ip.DstIP.String(), layers.UDPPort(dstPort), eip, ip, dstPort)
	case layers.LayerTypeTCP:
		tcp := layer.(*layers.TCP)
		dstPort = uint16(tcp.DstPort)
		bufferErr = gopacket.SerializeLayers(buffer, opts, ip, tcp, gopacket.Payload(tcp.Payload))
		go sendTCPPacket(buffer.Bytes(), ip.DstIP.String(), layers.TCPPort(dstPort), eip, ip, dstPort)
	case layers.LayerTypeICMPv4:
		icmp := layer.(*layers.ICMPv4)
		dstPort = 0
		bufferErr = gopacket.SerializeLayers(buffer, opts, ip, icmp, gopacket.Payload(icmp.Payload))
		go sendICMPPacket(buffer.Bytes(), ip.DstIP.String(), eip, ip, dstPort)
	}

	if bufferErr != nil {
		log.Printf("Error serializing layers: %v", bufferErr)
		return
	}
}

func sendUDPPacket(data []byte, dstIP string, dstPort layers.UDPPort, eip *net.IP, ip *layers.IPv4, port uint16) {
	portMutex.Lock()
	localPort, ok := portMappings.Load(connKey{srcIP: ip.SrcIP.String(), srcPort: port, dstIP: ip.DstIP.String(), dstPort: port})
	if !ok {
		localPort = randPorts[rand.Intn(len(randPorts))]
		portMappings.Store(connKey{srcIP: ip.SrcIP.String(), srcPort: port, dstIP: ip.DstIP.String(), dstPort: port}, localPort)
	}
	portMutex.Unlock()

	addr := net.UDPAddr{
		IP:   net.ParseIP(dstIP),
		Port: int(dstPort),
	}

	// Check if there's already a connection
	value, ok := connMappings.Load(connKey{srcIP: ip.SrcIP.String(), srcPort: port, dstIP: ip.DstIP.String(), dstPort: port})
	if !ok || value.(*connValue).udp == nil {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{
			IP:   *eip,
			Port: localPort.(int),
		})
		if err != nil {
			log.Printf("Error creating UDP connection: %v", err)
			return
		}
		connMappings.Store(connKey{srcIP: ip.SrcIP.String(), srcPort: port, dstIP: ip.DstIP.String(), dstPort: port}, &connValue{udp: conn})
		value = &connValue{udp: conn}
	}

	conn := value.(*connValue).udp

	_, err := conn.WriteToUDP(data, &addr)
	if err != nil {
		log.Printf("Error sending UDP packet: %v", err)
		return
	}

	buf := packetPool.Get().(*[]byte)
	defer packetPool.Put(buf)
	clearBuffer(buf)

	for {
		n, srcAddr, err := conn.ReadFromUDP(*buf)
		if err != nil {
			log.Printf("Error reading response: %v", err)
			return
		}

		if srcAddr.IP.String() == dstIP && srcAddr.Port == int(dstPort) {
			handleReturningPacket((*buf)[:n], connKey{srcIP: ip.SrcIP.String(), srcPort: port, dstIP: ip.DstIP.String(), dstPort: port})
		}
	}
}

func sendTCPPacket(data []byte, dstIP string, dstPort layers.TCPPort, eip *net.IP, ip *layers.IPv4, port uint16) {
	addr := net.TCPAddr{
		IP:   net.ParseIP(dstIP),
		Port: int(dstPort),
	}

	// Check if there's already a connection
	value, ok := connMappings.Load(connKey{srcIP: ip.SrcIP.String(), srcPort: port, dstIP: ip.DstIP.String(), dstPort: port})
	if !ok || value.(*connValue).conn == nil {
		conn, err := net.DialTCP("tcp", nil, &addr)
		if err != nil {
			log.Printf("Error creating TCP connection: %v", err)
			return
		}
		connMappings.Store(connKey{srcIP: ip.SrcIP.String(), srcPort: port, dstIP: ip.DstIP.String(), dstPort: port}, &connValue{conn: conn})
		value = &connValue{conn: conn}
	}

	conn := value.(*connValue).conn.(*net.TCPConn)

	_, err := conn.Write(data)
	if err != nil {
		log.Printf("Error sending TCP packet: %v", err)
		return
	}

	buf := packetPool.Get().(*[]byte)
	defer packetPool.Put(buf)
	clearBuffer(buf)

	for {
		n, err := conn.Read(*buf)
		if err != nil {
			log.Printf("Error reading response: %v", err)
			return
		}

		handleReturningPacket((*buf)[:n], connKey{srcIP: ip.SrcIP.String(), srcPort: port, dstIP: ip.DstIP.String(), dstPort: port})
	}
}

func sendICMPPacket(data []byte, dstIP string, eip *net.IP, ip *layers.IPv4, port uint16) {
	addr := net.UDPAddr{
		IP:   net.ParseIP(dstIP),
		Port: 0, // ICMP does not use ports, but net.UDPAddr is convenient for addressing
	}

	conn, err := net.ListenPacket("ip4:icmp", eip.String())
	if err != nil {
		log.Printf("Error creating ICMP connection: %v", err)
		return
	}
	defer conn.Close()

	_, err = conn.WriteTo(data, &addr)
	if err != nil {
		log.Printf("Error sending ICMP packet: %v", err)
		return
	}

	buf := packetPool.Get().(*[]byte)
	defer packetPool.Put(buf)
	clearBuffer(buf)

	for {
		n, _, err := conn.ReadFrom(*buf)
		if err != nil {
			log.Printf("Error reading response: %v", err)
			return
		}

		handleReturningPacket((*buf)[:n], connKey{srcIP: ip.SrcIP.String(), srcPort: port, dstIP: ip.DstIP.String(), dstPort: port})
	}
}

func clearBuffer(buf *[]byte) {
	for i := range *buf {
		(*buf)[i] = 0
	}
}

func handleReturningPacket(data []byte, originalKey connKey) {
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)

	geneveLayer := packet.Layer(layers.LayerTypeGeneve)
	if geneveLayer == nil {
		return
	}
	geneve, _ := geneveLayer.(*layers.Geneve)

	switch ip.Protocol {
	case layers.IPProtocolUDP:
		go handleReturningPacketCommon(ip, packet, geneve, originalKey, layers.LayerTypeUDP)
	case layers.IPProtocolTCP:
		go handleReturningPacketCommon(ip, packet, geneve, originalKey, layers.LayerTypeTCP)
	case layers.IPProtocolICMPv4:
		go handleReturningPacketCommon(ip, packet, geneve, originalKey, layers.LayerTypeICMPv4)
	default:
		log.Printf("Unhandled protocol in return packet: %v", ip.Protocol)
	}
}

func handleReturningPacketCommon(ip *layers.IPv4, packet gopacket.Packet, geneve *layers.Geneve, originalKey connKey, layerType gopacket.LayerType) {
	var layer gopacket.Layer

	switch layerType {
	case layers.LayerTypeUDP:
		layer = packet.Layer(layers.LayerTypeUDP)
	case layers.LayerTypeTCP:
		layer = packet.Layer(layers.LayerTypeTCP)
	case layers.LayerTypeICMPv4:
		layer = packet.Layer(layers.LayerTypeICMPv4)
	}

	if layer == nil {
		return
	}

	natKey := connKey{srcIP: ip.SrcIP.String(), srcPort: 0, dstIP: ip.DstIP.String(), dstPort: 0}
	if key, ok := connMappings.Load(natKey); ok {
		origKey := key.(connKey)
		ip.DstIP = net.ParseIP(origKey.srcIP)
		switch layerType {
		case layers.LayerTypeUDP:
			udp := layer.(*layers.UDP)
			udp.DstPort = layers.UDPPort(origKey.srcPort)
		case layers.LayerTypeTCP:
			tcp := layer.(*layers.TCP)
			tcp.DstPort = layers.TCPPort(origKey.srcPort)
		}

		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := gopacket.SerializeLayers(buffer, opts, ip, layer.(gopacket.SerializableLayer), gopacket.Payload(layer.LayerPayload())); err != nil {
			log.Printf("Error serializing layers: %v", err)
			return
		}

		go encapsulateAndSendGeneve(buffer.Bytes(), geneve, ip.SrcIP, layers.UDPPort(0))
	}
}

func encapsulateAndSendGeneve(data []byte, geneve *layers.Geneve, srcIP net.IP, srcPort layers.UDPPort) {
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	// Create a UDP layer for sending back
	udp := layers.UDP{
		SrcPort: layers.UDPPort(DefaultGenevePort),
		DstPort: srcPort,
	}

	// Create an IP layer for sending back
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("your_ip_here"), // This should be dynamic
		DstIP:    srcIP,
	}

	if err := udp.SetNetworkLayerForChecksum(&ip); err != nil {
		log.Printf("Error setting network layer for checksum: %v", err)
		return
	}

	// Manually serialize the Geneve header
	geneveBytes := make([]byte, 8)
	geneveBytes[0] = (geneve.Version << 6) | uint8(len(geneve.Options)/4)
	geneveBytes[1] = boolToByte(geneve.CriticalOption) << 7 // Assumes CriticalOption is a boolean
	binary.BigEndian.PutUint16(geneveBytes[2:], uint16(geneve.Protocol))
	binary.BigEndian.PutUint32(geneveBytes[4:], geneve.VNI<<8)

	if err := gopacket.SerializeLayers(buffer, opts, &ip, &udp, gopacket.Payload(geneveBytes), gopacket.Payload(data)); err != nil {
		log.Printf("Error serializing layers: %v", err)
		return
	}

	go sendPacket(buffer.Bytes(), srcIP.String(), udp.DstPort)
}

func boolToByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func sendPacket(data []byte, dstIP string, dstPort layers.UDPPort) {
	addr := net.UDPAddr{
		IP:   net.ParseIP(dstIP),
		Port: int(dstPort),
	}

	localAddr := &net.UDPAddr{
		IP:   net.IPv4zero, // Use default IP (0.0.0.0)
		Port: 0,            // 0 means the OS will pick a random port
	}
	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		log.Printf("Error creating UDP connection: %v", err)
		return
	}
	defer conn.Close()

	_, err = conn.WriteToUDP(data, &addr)
	if err != nil {
		log.Printf("Error sending UDP packet: %v", err)
		return
	}

	buf := packetPool.Get().(*[]byte)
	defer packetPool.Put(buf)
	clearBuffer(buf)

	for {
		n, srcAddr, err := conn.ReadFromUDP(*buf)
		if err != nil {
			log.Printf("Error reading response: %v", err)
			return
		}

		if srcAddr.IP.String() == dstIP && srcAddr.Port == int(dstPort) {
			handleReturningPacket((*buf)[:n], connKey{srcIP: addr.IP.String(), srcPort: uint16(addr.Port), dstIP: dstIP, dstPort: uint16(dstPort)})
		}
	}
}
