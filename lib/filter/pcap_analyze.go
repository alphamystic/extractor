package filter

import (
	//"fmt"
	dfn"github.com/alphamystic/extractor/lib/definers"
)


func (filter *Filter) PCAPAnalyze() error {
	if filter.Protocol == "ALL" {
		//analyze everything
		return nil
	}
  for _,gp := range filter.Grouped {
    switch gp.Protocol {
      case "TCP":
        return TcpAnalyzer(gp)
      case "UDP":
      case "DNS":
      case "ICMP":
      default:
        return dfn.USP
    }
  }
  return dfn.NPF
}
