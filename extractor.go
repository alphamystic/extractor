package main

import (
  "os"
  "fmt"
  "log"

  "github.com/google/gopacket"

  flt"github.com/alphamystic/extractor/lib/filter"
  "github.com/alphamystic/extractor/lib/utils"
)


func main(){
  if len(os.Args) != 2 {
    log.Fatalf("[+] Usage: %s <PCAP File>\n",os.Args[0])
  }
  pcapFile := os.Args[1]
  var (
    err error
    numberOfPackets int
  )
  data := &flt.Data{
    FileName: pcapFile,
  }
  if err = data.GetHandle(pcapFile); err != nil {
    log.Fatalf("[-] ",err)
  }
  defer data.Hnd.Close()
  var pairs []*flt.CommunicationPair
  packetSource := gopacket.NewPacketSource(data.Hnd,data.Hnd.LinkType())
  for packet := range packetSource.Packets() {
    numberOfPackets = numberOfPackets + 1
    var pair *flt.CommunicationPair
    if pair = flt.PacketHandler(packet); pair == nil{
      continue
    }
    pairs = append(pairs,pair)
  }
  utils.PrintInformation(fmt.Sprintf("[+]  Arranged %d packets.",numberOfPackets))
  var analyzer flt.Analyzer
  analyzer = &flt.Filter{}
  analyzer.Sort(pairs)
  if err := analyzer.PCAPAnalyze(); err != nil{
    fmt.Sprintf("[-]  Error analyzing pcap packets: %s",err)
  }
  /*
  for _, p := range pairs {
    //fmt.Printf("Packets for %s to %s in the protocol %s with size %d\n", p.SourceIP, p.DestinationIP, p.Protocol, p.Size)
  }*/
}
