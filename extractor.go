package main

import (
  "io"
  "os"
  "fmt"
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
    "zip": []byte{0x50, 0x4B, 0x03, 0x04},
    "png": []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
}

/*
func (ps *PStream) run() {
  endTmp := &bytes.Buffer{} // Final buffer to accumulate all stream data.
  tmp := make([]byte, 4096) // Temp buffer for reading stream data.
  var fileTypeDetected string
  for {
    n, err := ps.r.Read(tmp)
    if n > 0 {
      data := tmp[:n]
      endTmp.Write(data) // Append to final buffer regardless of file type detection status.
      if fileTypeDetected == "" {
        // Attempt to detect the file type if not already detected.
        for fileType, signature := range fileTypeSignatures {
          if bytes.Contains(endTmp.Bytes(), signature) {
            fileTypeDetected = fileType
            fmt.Println("[+] Detected file type:", fileType)
            // No break here to ensure all data is read; fileTypeDetected prevents re-checking.
          }
        }
      }
    }
    if err == io.EOF {
      break // End of stream.
    } else if err != nil {
      fmt.Printf("[-] Error reading stream: %v\n", err)
      return
    }
  }
  if fileTypeDetected != "" {
    // Save the detected file to disk.
    saveFile(endTmp.Bytes(), fileTypeDetected)
  }
}
*/

func (ps *PStream) run() {
  endTmp := &bytes.Buffer{} // Buffer to accumulate stream data
    tmp := make([]byte, 4096) // Temp buffer for reading stream data
    var fileTypeDetected string

    for {
        n, err := ps.r.Read(tmp)
        if n > 0 {
            data := tmp[:n]
            // Append read data to the buffer
            endTmp.Write(data)

            // If file type hasn't been detected yet, attempt to detect it
            if fileTypeDetected == "" {
                for fileType, signature := range fileTypeSignatures {
                    if bytes.Contains(endTmp.Bytes(), signature) {
                        fileTypeDetected = fileType
                        fmt.Println("[+] Detected file type:", fileType)
                        // Once file type is detected, no need to check again
                        break
                    }
                }
            }
        }

        // If EOF, exit loop
        if err == io.EOF {
            break
        } else if err != nil {
            fmt.Printf("[-] Error reading stream: %v\n", err)
            return
        }
    }

    // After reading the entire stream, if a file type was detected, save the data
    if fileTypeDetected != "" {
        saveFile(endTmp.Bytes(), fileTypeDetected)
    }
}

func saveFile(data []byte, fileType string) {
    // Generate a unique filename for each saved file.
    exeCounter++
    filename := fmt.Sprintf("extracted_%d.%s", exeCounter, fileType)
    err := os.WriteFile(filename, data, 0644)
    if err != nil {
        fmt.Printf("[-] Failed to save file %s: %v\n", filename, err)
        return
    }
    fmt.Printf("[+] Saved %s successfully.\n", filename)
}


func writePayloadToFile(payload []byte, filename string) {
  file, err := os.Create(filename)
  if err != nil {
    fmt.Printf("[-] Failed to create file: %v\n", err)
    return
  }
  defer file.Close()
  _, err = file.Write(payload)
  if err != nil {
    fmt.Printf("Failed to write payload to file: %v\n", err)
    return
  }
  fmt.Printf("[+]Written %d bytes to %s\n", len(payload), filename)
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
