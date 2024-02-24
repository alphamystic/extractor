package main

import (
  "io"
  "os"
  "fmt"
  "sync"
  "bytes"
  //"strings"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "github.com/google/gopacket/pcap"
  "github.com/google/gopacket/tcpassembly"
  "github.com/google/gopacket/tcpassembly/tcpreader"
)

var (
    pcapFile    string
    exeCounter  int
    streamStore = make(map[string]*bytes.Buffer)
)

type streamFactory struct{}

type PStream struct {
  net, transport gopacket.Flow
  r tcpreader.ReaderStream
  fileLock sync.Mutex
}

func (f *streamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
  ps := &PStream{
    net: net,
    transport: transport,
    r: tcpreader.NewReaderStream(),
  }
  go ps.run() // Start processing the stream in a goroutine
  return &ps.r // Implement tcpassembly.Stream interface
}

// fileTypeSignatures holds the byte signatures of different file types for detection.
var fileTypeSignatures = map[string][]byte{
  "exe": []byte{0x4D, 0x5A},
  //"zip": []byte{0x50, 0x4B, 0x03, 0x04},
  //"png": []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
}

func saveFile(data []byte, fileTypeDetected string,lock *sync.Mutex) {
  lock.Lock() // Lock before writing to the file
  defer lock.Unlock() // Ensure the lock is released after writing
	// This is a simplified example. You should add error checking and handling.
	tempFileName := "temp_file"
	finalFileName := fmt.Sprintf("%s.%s", tempFileName, fileTypeDetected)
  file, err := os.OpenFile(finalFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("[-] Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		fmt.Printf("[-] Error writing to file: %v\n", err)
	}

	/*os.WriteFile(tempFileName, data, 0644) // Write the data to a temporary file
	os.Rename(tempFileName, finalFileName) // Rename the file based on detected file type
  */
	fmt.Printf("File saved as %s\n", finalFileName)
}

func (ps *PStream) run() {
  tmp := make([]byte, 4096) // Temp buffer for initial read and detection
	n, err := ps.r.Read(tmp)
	if err != nil && err != io.EOF {
		fmt.Printf("[-] Error reading stream: %v\n", err)
		return
	}
	// Attempt to detect file type
	var fileTypeDetected string
	data := tmp[:n]
	for fileType, signature := range fileTypeSignatures {
		if bytes.Contains(data, signature) {
			fileTypeDetected = fileType
			fmt.Println("[+] Detected file type:", fileType)
			break
		}
	}
  // write the data to file then start stream reading to EOF
  saveFile(data,fileTypeDetected,&ps.fileLock)
  fmt.Println("Done with the first reading......")
  for {
		n, err := ps.r.Read(tmp)
		if n > 0 {
			data := tmp[:n]
      // or just write and let save append
      saveFile(data,fileTypeDetected,&ps.fileLock)
		}
		// If EOF, exit loop
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Printf("[-] Error reading stream: %v\n", err)
			return
		}
	}
}

func main() {
  if len(os.Args) != 2 {
    fmt.Println("[+] Usage: go run main.go <pcap file>")
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
  packetSource.NoCopy = true
  for packet := range packetSource.Packets() {
    if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
      continue
    }
    tcp := packet.TransportLayer().(*layers.TCP)
    assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
  }
}
