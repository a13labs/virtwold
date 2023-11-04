//
// Virtual Wake-on-LAN
//
// Listens for a WOL magic packet (UDP), then connects to the local libvirt socket and finds a matching VM
// If a matching VM is found, it is started (if not already running)
//
// Assumes the VM has a static MAC configured
// Assumes libvirtd connection is at /var/run/libvirt/libvirt-sock
//
// Filters on len=102 and len=144 (WOL packet) and len=234 (WOL packet with password)

package main

import (
	"flag"
	"log"
	"net"
	"strings"
	"time"

	"github.com/antchfx/xmlquery"
	"github.com/digitalocean/go-libvirt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var iface string           // Interface we'll listen on
var libvirtAddrType string // Interface we'll listen on
var libvirtAddr string     // Interface we'll listen on

func main() {
	var buffer = int32(1600)                        // Buffer for packets received
	var filter = "ether proto 0x0842 or udp port 9" // PCAP filter to catch UDP WOL packets

	flag.StringVar(&iface, "interface", "", "Network interface name to listen on")
	flag.StringVar(&libvirtAddrType, "socket", "unix", "Libvirt socket type")
	flag.StringVar(&libvirtAddr, "addr", "/var/run/libvirt/libvirt-sock", "Libvirt address")
	flag.Parse()

	if !deviceExists(iface) {
		log.Fatalf("Unable to open device: %s", iface)
	}

	handler, err := pcap.OpenLive(iface, buffer, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open device: %v", err)
	}
	defer handler.Close()

	log.Printf("Using device: %s", iface)
	if err := handler.SetBPFFilter(filter); err != nil {
		log.Fatalf("Something in the BPF went wrong!: %v", err)
	}

	// Handle every packet received, looping forever
	source := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range source.Packets() {
		// Called for each packet received
		link := packet.LinkLayer()
		mac := link.LinkFlow().Dst().String()
		log.Printf("Received WOL packet.\n")
		if WakeVirtualMachine(mac) {
			log.Printf("Matched VM with MAC address on this host.\n")
		} else {
			log.Printf("No VM with matched MAC address found on this host.\n")
		}
	}
}

func WakeVirtualMachine(mac string) bool {
	// Connect to the local libvirt socket
	c, err := net.DialTimeout(libvirtAddrType, libvirtAddr, 2*time.Second)
	if err != nil {
		log.Fatalf("Failed to dial libvirt: %v", err)
	}

	l := libvirt.New(c)
	if err := l.Connect(); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	// Get a list of all VMs (aka Domains) configured so we can loop through them
	flags := libvirt.ConnectListDomainsActive | libvirt.ConnectListDomainsInactive
	domains, _, err := l.ConnectListAllDomains(1, flags)
	if err != nil {
		log.Fatalf("Failed to retrieve domains: %v", err)
	}

	macFound := false
	for _, d := range domains {
		//log.Printf("%d\t%s\t%x\n", d.ID, d.Name, d.UUID)

		// Now we get the XML Description for each domain
		xmldesc, err := l.DomainGetXMLDesc(d, 0)
		if err != nil {
			log.Fatalf("failed retrieving interfaces: %v", err)
		}

		// Feed the XML output into xmlquery
		querydoc, err := xmlquery.Parse(strings.NewReader(xmldesc))
		if err != nil {
			log.Fatalf("Failed to parse XML: %v", err)
		}

		// Perform an xmlquery to look for the MAC address in the XML
		for _, list := range xmlquery.Find(querydoc, "//domain/devices/interface/mac/@address") {
			// Use the strings.EqualFold function to do a case-insensitive comparison of MACs
			if strings.EqualFold(list.InnerText(), mac) {
				macFound = true
				stateInt, _, err := l.DomainGetState(d, 0)
				if err != nil {
					log.Fatalf("Failed to check domain state: %v", err)
				}

				state := libvirt.DomainState(stateInt)
				// log.Printf("Domain state is %v\n", state)

				switch state {
				case libvirt.DomainShutoff, libvirt.DomainCrashed:
					log.Printf("Waking system: %s at MAC %s\n", d.Name, mac)
					if err := l.DomainCreate(d); err != nil {
						log.Fatalf("Failed to start domain: %v", err)
					}
				case libvirt.DomainPmsuspended:
					log.Printf("PM Wakeup system: %s at MAC %s\n", d.Name, mac)
					if err := l.DomainPmWakeup(d, 0); err != nil {
						log.Fatalf("Failed to pm wakeup domain: %v", err)
					}
				case libvirt.DomainPaused:
					log.Printf("Resume system: %s at MAC %s\n", d.Name, mac)
					if err := l.DomainResume(d); err != nil {
						log.Fatalf("Failed to resume domain: %v", err)
					}
				default:
					log.Printf("System %s is already running or in a state that cannot be woken from. State: %d\n", d.Name, state)
				}

				break
			}
		}
	}

	if err := l.Disconnect(); err != nil {
		log.Fatalf("Failed to disconnect: %v", err)
	}

	return macFound
}

// Check if the network device exists
func deviceExists(interfacename string) bool {
	if interfacename == "" {
		log.Printf("No interface to listen on specified\n\n")
		flag.PrintDefaults()
		return false
	}
	devices, err := pcap.FindAllDevs()

	if err != nil {
		log.Panic(err)
	}

	for _, device := range devices {
		if device.Name == interfacename {
			return true
		}
	}
	return false
}
