package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// communicationPair holds a source-destination pair as a string
type communicationPair struct {
	srcIP, dstIP string
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <PCAP file>\n", os.Args[0])
	}

	pcapFile := os.Args[1]

	// Open the PCAP file
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// A map to keep track of communication pairs and their corresponding files
	commFiles := make(map[communicationPair]*os.File)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		// Create a pair for each communication
		pair := communicationPair{srcIP: ip.SrcIP.String(), dstIP: ip.DstIP.String()}

		// Check for TCP layer
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			if len(tcp.Payload) > 0 {
				// Check if we already have a file for this communication
				if _, ok := commFiles[pair]; !ok {
					// Create a new file for this communication pair
					filename := fmt.Sprintf("dmp/payload_%s_to_%s.bin", strings.ReplaceAll(pair.srcIP, ".", "_"), strings.ReplaceAll(pair.dstIP, ".", "_"))
					commFiles[pair], err = os.Create(filename)
					if err != nil {
						log.Fatalf("Failed to create file for %v: %v\n", pair, err)
					}
					defer commFiles[pair].Close()
					fmt.Printf("Created file: %s\n", filename)
				}

				// Write the payload to the file
				if _, err := commFiles[pair].Write(tcp.Payload); err != nil {
					log.Printf("Failed to write payload to file for %v: %v\n", pair, err)
				}
			}
		}
	}

	for _, file := range commFiles {
		file.Close()
	}

	fmt.Println("Payloads dumped successfully for all communication pairs.")
}
