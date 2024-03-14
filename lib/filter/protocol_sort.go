package filter

import (
  "fmt"
)

// SortPackets groups packets by their protocol.
func (filter *Filter) Sort(pairs []*CommunicationPair) {
  fmt.Println("Soorrtttitiiiiiinnggg")
  var groupedPair []*GroupedPair
  var tcpPairs []*CommunicationPair
  var udpPairs []*CommunicationPair
  var icmpPairs []*CommunicationPair
  var dnsPairs []*CommunicationPair
  var ftpPairs []*CommunicationPair
  for _, pair := range pairs {
    switch pair.Protocol {
    case "TCP":
      tcpPairs = append(tcpPairs,pair)
    case "UDP":
      udpPairs = append(udpPairs,pair)
    case "ICMP":
      icmpPairs = append(icmpPairs,pair)
    case "FTP":
      ftpPairs = append(ftpPairs,pair)
    case "DNS":
      dnsPairs = append(dnsPairs,pair)
    default: continue
    }
  }
  groupedPair = append(groupedPair,&GroupedPair{
    Protocol: "TCP",
    Pairs: tcpPairs,
  })
  groupedPair = append(groupedPair,&GroupedPair{
    Protocol: "UDP",
    Pairs: udpPairs,
  })
  groupedPair = append(groupedPair,&GroupedPair{
    Protocol: "ICMP",
    Pairs: icmpPairs,
  })
  groupedPair = append(groupedPair,&GroupedPair{
    Protocol: "DNS",
    Pairs: dnsPairs,
  })
  filter.Grouped = groupedPair
}


/*
func SortPackets(pairs []*CommunicationPair) []*GroupedPair {
  grouped := make(map[PType][]*CommunicationPair)
  var pt PType
	for _, pair := range pairs {
    switch pair.Protocol {
     case "TCP":
       pt = TCP
		 case "UDP":
       pt = UDP
		 case "DNS":
       pt = DNS
		 case "ICMP":
       pt = ICMP
		 default:
       continue
		}
		grouped[pt] = append(grouped[pt], pair)
	}
	var groupedPairs []*GroupedPair
	for protocol, newPairs := range grouped {
    groupedPairs = append(groupedPairs, &GroupedPair{
      Protocol: protocol,
			GoupedPairs: newPairs,
		})
	}
	return groupedPairs
}
*/
