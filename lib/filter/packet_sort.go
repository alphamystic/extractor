package filter


import(
  "fmt"
  "github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Data struct {
  FileName string
  Hnd *pcap.Handle
}

// this will be fed into anylis to determine wth it is
type CommunicationPair struct {
  SourceIP string
  DestinationIP string
  Protocol string
  Data []byte
  Pkt gopacket.Packet
  Size int
}

type GroupedPair struct {
  Protocol string//PType
  Pairs []*CommunicationPair
}

type PType int
const (
  TCP PType = iota
  UDP
  DNS
  ICMP
)

func (pt PType) GetProtocolType() string {
  var protocol string
  switch pt {
  case TCP:
    protocol = "TCP"
  case UDP:
    protocol = "UDP"
  case DNS:
    protocol = "DNS"
  case ICMP:
    protocol = "ICMP"
  default:
    return  ""
  }
  return protocol
}

func (d *Data) GetHandle(fileName string) error {
  handle,err := pcap.OpenOffline(fileName)
  if err != nil {
    return fmt.Errorf("Error opening pcap file: %q",err)
  }
  d.Hnd = handle
  return nil
}


type UDPSort struct{}
type DNSSort struct{}
type ICMPSort struct{}
