package filter

import (
  "sort"
)

func (gp *GroupedPair) SortByTime() {
  sort.Slice(gp.Pairs, func(i, j int) bool {
    return gp.Pairs[i].Pkt.Metadata().CaptureInfo.Timestamp.Before(gp.Pairs[j].Pkt.Metadata().CaptureInfo.Timestamp)
  })
}
