package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var pcapFile string

type streamFactory struct{}

type PStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	data           bytes.Buffer
	fileLock       sync.Mutex
}

func (f *streamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	ps := &PStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go ps.run()
	return &ps.r
}

var fileTypeSignatures = map[string][]byte{
	"exe": []byte{0x4D, 0x5A},
}

func saveFile(data []byte, fileTypeDetected string) {
	tempFileName := fmt.Sprintf("temp_file.%s", fileTypeDetected)
	if err := os.WriteFile(tempFileName, data, 0644); err != nil {
		fmt.Printf("[-] Error writing file: %s\n", err)
		return
	}
	fmt.Printf("[+] File saved as %s\n", tempFileName)
}

func (ps *PStream) run() {
	var fileTypeDetected string
	buffer := &bytes.Buffer{}
	// Read all data from the stream
	io.Copy(buffer, &ps.r)
	data := buffer.Bytes()
	// Attempt to detect file type
	for fileType, signature := range fileTypeSignatures {
		if bytes.Contains(data, signature) {
			fileTypeDetected = fileType
			fmt.Println("[+] Detected file type:", fileType)
			break
		}
	}
	if fileTypeDetected != "" {
		saveFile(data, fileTypeDetected)
	} else {
		fmt.Println("[-] File type could not be detected.")
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run main.go <pcap file>")
		return
	}

	pcapFile = os.Args[1]
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		fmt.Printf("[-] Failed to open pcap file: %v\n", err)
		return
	}
	defer handle.Close()

	factory := &streamFactory{}
	pool := tcpassembly.NewStreamPool(factory)
	assembler := tcpassembly.NewAssembler(pool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
			continue
		}
		tcp := packet.TransportLayer().(*layers.TCP)
		assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
	}
}
