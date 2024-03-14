package filter

import (
  "fmt"
	//dfn"github.com/alphamystic/extractor/lib/definers"
)


func TcpAnalyzer(gp *GroupedPair) error {
  for _,pair := range gp.Pairs {
    if pair.Protocol == "TCP" {
      //dump to file
      fmt.Println("Dumping.....",pair.SourceIP)
      // fmt.Sprintf("payload_%s_to_%s.bin", strings.ReplaceAll(pair.srcIP, ".", "_"), strings.ReplaceAll(pair.dstIP, ".", "_"))
      pair.DumpPayloadToFile("dumpp/testtcp")
    } else {
      return fmt.Errorf("Supports only TCP protocol.........")
    }
  }
  return nil
}
