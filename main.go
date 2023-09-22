package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"text/tabwriter"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	ArgsListDevice  bool
	ArgsIface       string
	ArgsPushAddress string
	ArgsPushPort    int
)

var (
	DateChanel = make(chan []byte, 1024)
)

func init() {
	flag.BoolVar(&ArgsListDevice, "l", false, "list network device")
	flag.StringVar(&ArgsIface, "i", "eth0", "network iface")
	flag.StringVar(&ArgsPushAddress, "s", "localhost", "remote addr")
	flag.IntVar(&ArgsPushPort, "p", 60923, "remote port")
}

func dial(network string, address string, port int) (net.Conn, error) {
	switch network {
	case "udp":
		return net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(address), Port: port})
	default:
		return nil, fmt.Errorf("unknown network %s", network)
	}
}

func push(conn net.Conn) {
	for data := range DateChanel {
		conn.Write(data)
	}
}

func printDevice() {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalln(err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 3, ' ', tabwriter.StripEscape)
	fmt.Fprintln(w, "name\taddress")
	for _, i := range ifs {
		fmt.Fprintf(w, "%s\t%s\n", i.Name, i.Addresses)
	}
	w.Flush()
}

func main() {
	flag.Parse()
	if ArgsListDevice {
		printDevice()
		return
	}
	conn, err := dial("udp", ArgsPushAddress, ArgsPushPort)
	if err != nil {
		log.Fatalln(err)
	}
	go push(conn)

	var handle *pcap.Handle
	inactive, err := pcap.NewInactiveHandle(ArgsIface)
	if err != nil {
		log.Fatalf("could not create: %v", err)
	}
	defer inactive.CleanUp()
	if handle, err = inactive.Activate(); err != nil {
		log.Fatalf("PCAP Activate error:%v", err)
	}
	defer handle.Close()
	dec, _ := gopacket.DecodersByLayerName["Ethernet"]
	source := gopacket.NewPacketSource(handle, dec)
	source.Lazy = false
	source.NoCopy = true
	source.DecodeStreamsAsDatagrams = true
	log.Printf("pcap is runing, server:%s,port:%d\n", ArgsPushAddress, ArgsPushPort)
	for packet := range source.Packets() {
		select {
		case DateChanel <- packet.Data():
		default:
		}
	}
}
