package filter

import (
  "os"
  "fmt"
  "strings"
  "github.com/google/gopacket"
	"github.com/google/gopacket/layers"
  "github.com/alphamystic/extractor/lib/utils"
)

/*
    If a packet has zero payload then it's "Discarded" For loop handles that
    once a packet has been handled, the pair contains everything about the packet
*/
func PacketHandler(packet gopacket.Packet) *CommunicationPair {
  ipLayer := packet.Layer(layers.LayerTypeIPv4)
  if ipLayer == nil { return nil }
  ip,_ := ipLayer.(*layers.IPv4)
  pair := &CommunicationPair{
    SourceIP: ip.SrcIP.String(),
    DestinationIP: ip.DstIP.String(),
    Pkt: packet,
  }
  //check for the layer types and switch it out
  if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
    tcp, _ := tcpLayer.(*layers.TCP)
    pair.Protocol = "TCP"
    if len(tcp.Payload) > 0 {
      pair.Size = len(tcp.Payload)
      pair.Data = tcp.Payload
      return pair
    }
  } else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
    fmt.Println("[+] Found a UDP packet")
    udp, _ := udpLayer.(*layers.UDP)
    pair.Protocol = "UDP"
    if len(udp.Payload) > 0 {
      pair.Size = len(udp.Payload)
      pair.Data = udp.Payload
      return pair
    }
  } else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
    icmp, _ := icmpLayer.(*layers.ICMPv4)
    pair.Protocol = "ICMP"
    if len(icmp.Payload) > 0 {
      pair.Size = len(icmp.Payload)
      pair.Data = icmp.Payload
      return pair
    }
  } else if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
    // @TODO
    // For DNS, we need to handle it differently, possibly printing the DNS query or response instead of raw payload
    pair.Protocol = "UDP"
    dns, _ := dnsLayer.(*layers.DNS)
    // Find a way to handle DNS records differently
    pair.Data = []byte(fmt.Sprintf("DNS ID: %d, QR: %t, OpCode: %d", dns.ID, dns.QR, dns.OpCode))
    pair.Size = len(pair.Data)
    return pair
  } /* else if  {
    //create an aFTP handler
    continue
    }
    */
  return nil
}


func (cp *CommunicationPair) DumpPayloadToFile(dir string) error {
  name := utils.GenerateUUID() // There can be multiple packets with similar source IP and destination IP.
  ipdst := fmt.Sprintf("_%s_to_%s.bin", strings.ReplaceAll(cp.SourceIP, ".", "_"), strings.ReplaceAll(cp.DestinationIP, ".", "_"))
  name = name + ipdst
  if err := os.MkdirAll(dir,os.ModePerm); err != nil  {
    return fmt.Errorf("failed to create directory: %v", err)
  }
  dir = dir + name
  fmt.Println("directory name...",dir)
  file, err := os.OpenFile(dir, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
  if err != nil {
    return fmt.Errorf("error opening/creating file: %v", err)
  }
  defer file.Close()

  // Append the data to the file
  if _, err := file.Write(cp.Data); err != nil {
    return fmt.Errorf("error writing payload to file: %v", err)
  }
  return nil
}
