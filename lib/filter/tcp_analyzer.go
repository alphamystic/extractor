package filter

import (
  "fmt"
	"github.com/alphamystic/extractor/lib/utils"
)


func TcpAnalyzer(gp *GroupedPair) error {
  // sort by different tcp protocols
  // arrange each by time (obviouly it should be a different gp for each)
  gp.SortByTime()
  st := utils.GenerateUUID()
  st = utils.Md5Hash(st)
  for _,pair := range gp.Pairs {
    if pair.Protocol == "TCP" {
      //dump to file
      fmt.Println("Dumping.....",pair.SourceIP)
      // fmt.Sprintf("payload_%s_to_%s.bin", strings.ReplaceAll(pair.srcIP, ".", "_"), strings.ReplaceAll(pair.dstIP, ".", "_"))
      dir := "dumpp/"
      dir = dir + string(st) + "/"
      fmt.Println("Directory is: ",dir)
      pair.DumpPayloadToFile(dir)
    } else {
      return fmt.Errorf("Supports only TCP protocol.........")
    }
  }
  return nil
}

type TCPSort struct {
  HTTP []*CommunicationPair
  HTTPS []*CommunicationPair
  FTP []*CommunicationPair
  SSH []*CommunicationPair
}

func (ts *TCPSort) HTTPSort(pairs []*CommunicationPair) error {
  return nil
}

func (ts *TCPSort) HTTPSSort(pairs []*CommunicationPair) error {
  return nil
}

func (ts *TCPSort) HTTPSort(pairs []*CommunicationPair) error {
  return nil
}

func (ts *TCPSort) SSHSort(pairs []*CommunicationPair) error {
  return nil
}

func (ts *TCPSort) FTPSort(pairs []*CommunicationPair) error {
  return nil
}



func (ts *TCPSort) SortTCP() {
  go func(pairs []*CommunicationPair){
    if err := ts.HTTPSort(); err != nil {
      fmt.Sprintf("[-] Error sorting HTTP packets: %q",err)
    }
  }()

  go func(pairs []*CommunicationPair){
    if err := ts.HTTPSort(); err != nil {
      fmt.Sprintf("[-] Error sorting HTTP packets: %q",err)
    }
  }()

  go func(pairs []*CommunicationPair){
    if err := ts.SSHSort(); err != nil {
      fmt.Sprintf("[-] Error sorting HTTP packets: %q",err)
    }
  }()

  go func(pairs []*CommunicationPair){
    if err := ts.FTPSort(); err != nil {
      fmt.Sprintf("[-] Error sorting HTTP packets: %q",err)
    }
  }()
}


// determineProtocol tries to determine the specific protocol (HTTP, HTTPS, FTP, SSH) based on the packet content
func determineProtocol(pkt gopacket.Packet) string {
    // This is a simplified version. Real-world applications may need a more thorough analysis.
    if pkt.ApplicationLayer() != nil {
        payload := string(pkt.ApplicationLayer().Payload())
        // Check for specific protocol signatures in the payload
        // This is overly simplistic and for demonstration. You'd have more complex logic here.
        if layers.LayerTypeTLS.Matches(pkt.ApplicationLayer().LayerType()) {
            return "HTTPS"
        } else if contains(payload, "SSH") {
            return "SSH"
        } else if contains(payload, "HTTP") {
            return "HTTP"
        } else if contains(payload, "FTP") {
            return "FTP"
        }
    }
    return "Unknown"
}

// contains is a simple helper to check if the payload contains certain protocol signatures
func contains(s, substr string) bool {
    return len(s) >= len(substr) && s[:len(substr)] == substr
}
