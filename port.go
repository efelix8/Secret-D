package main

import (
	"fmt"
	"net"
	"sync"
	"log"
	"os"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type PortResult struct {
	port   int
	status string
}

func sendFin(target string, port int) {
	handle, err := pcap.OpenLive("eth0", 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP("your_source_ip"),
		DstIP:    net.ParseIP(target),
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(port),
		Seq:     1105024978,
		Window:  14600,
		ACK:     false,
		SYN:     false,
		FIN:     true,
		PSH:     false,
		URG:     false,
		RST:     false,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer)

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Sent FIN packet to %s:%d\n", target, port)
}

func sendXmas(target string, port int) {
	handle, err := pcap.OpenLive("eth0", 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP("your_source_ip"),
		DstIP:    net.ParseIP(target),
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(port),
		Seq:     1105024978,
		Window:  14600,
		ACK:     false,
		SYN:     false,
		FIN:     true,
		PSH:     true,
		URG:     true,
		RST:     false,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer)

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Sent Xmas packet to %s:%d\n", target, port)
}

func sendWindow(target string, port int) {
	handle, err := pcap.OpenLive("eth0", 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP("your_source_ip"),
		DstIP:    net.ParseIP(target),
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(port),
		Seq:     1105024978,
		Window:  14600,
		ACK:     false,
		SYN:     false,
		FIN:     false,
		PSH:     false,
		URG:     false,
		RST:     false,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer)

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Sent Window packet to %s:%d\n", target, port)
}

func portScan(protocol string, ip string, port int, results chan<- PortResult) {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.Dial(protocol, address)
	if err != nil {
		results <- PortResult{port: port, status: "closed"}
		return
	}
	conn.Close()
	results <- PortResult{port: port, status: "open"}
}

func checkActivity(ip string){
	targetIP := net.ParseIP(ip)

	echoRequest := icmp.Message{
		Type: ipv4.ICMPTypeEcho, // ICMP type: Echo Request
		Code: 0,                 // Code: 0
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff, // Use a random ID, 16-bit and unique to the PC
			Seq:  1,                    // ICMP sequence
			Data: []byte("Hello ICMP"), // ICMP data
		},
	}

	// Convert ICMP message to bytes
	b, err := echoRequest.Marshal(nil)
	if err != nil {
		log.Fatal(err)
	}

	// Send ICMP message to the target
	start := time.Now()
	conn, err := net.DialIP("ip4:icmp", nil, &net.IPAddr{IP: targetIP})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	_, err = conn.Write(b)
	if err != nil {
		log.Fatal(err)
	}

	// Wait for a reply
	reply := make([]byte, 1500)
	err = conn.SetReadDeadline(time.Now().Add(3 * time.Second)) // Expect a reply within 3 seconds
	if err != nil {
		log.Fatal(err)
	}
	n, err := conn.Read(reply)
	if err != nil {
		log.Fatal("No reply")
	}

	// Parse ICMP reply
	rm, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		log.Fatal(err)
	}
	duration := time.Since(start)

	// ICMP reply output
	fmt.Printf("ICMP Reply from %s: seq=%d time=%v\n", targetIP.String(), rm.Body.(*icmp.Echo).Seq, duration)

	echoRequestBytes, err := echoRequest.Marshal(nil)
	if err != nil {
		fmt.Println("Error creating ICMP packet:", err)
		return
	}

	_, err = conn.Write(echoRequestBytes)
	if err != nil {
		fmt.Println("Error sending ICMP packet:", err)
		return
	}

	reply = make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = conn.Read(reply)
	if err != nil {
		fmt.Println("Target is not active or did not respond.")
		return
	}

	echoReply, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		fmt.Println("Error parsing ICMP reply:", err)
		return
	}

	switch echoReply.Type {
	case ipv4.ICMPTypeEchoReply:
		fmt.Println("Target is active!")
	default:
		fmt.Println("Target did not respond.")
	}
}

func main() {
	var (
		ip          string
		port1, port2 int
		protocol    string
		closedChoice int
	)
	fmt.Print("Enter the IP address: ")
	fmt.Scan(&ip)

	fmt.Print("Enter the start port: ")
	fmt.Scan(&port1)

	fmt.Print("Enter the end port: ")
	fmt.Scan(&port2)

	fmt.Print("Select the protocol: \n [1] TCP \n [2] UDP \n \n Enter number: ")
	var protocolChoice int
	fmt.Scan(&protocolChoice)

	fmt.Print("Do you want to see closed ports? \n [1] Yes \n [2] No \n Please enter a number: ")
	fmt.Scan(&closedChoice)

	if protocolChoice == 1 {
		protocol = "tcp"
	} else {
		protocol = "udp"
	}

	results := make(chan PortResult)

	for port := port1; port <= port2; port++ {
		go portScan(protocol, ip, port, results)
	}

	openPorts := []int{}
	closedPorts := []int{}

	for port := port1; port <= port2; port++ {
		result := <-results
		if result.status == "open" {
			openPorts = append(openPorts, result.port)
		} else {
			closedPorts = append(closedPorts, result.port)
		}
	}

	close(results)

	fmt.Println("Open ports")
	for _, port := range openPorts {
		fmt.Printf("%d\n", port)
	}

	if closedChoice == 1 {
		fmt.Println("Closed ports")
		for _, port := range closedPorts {
			fmt.Printf("%d\n", port)
		}
	}

	fmt.Println("The scan is complete.")
}
