package handlers

import(
  //"fmt"
  "net/http"
//  "loki/lib/utils"
//  "loki/lib/workers"
)

func (hnd *Handler) PcapAnalyzer(res http.ResponseWriter, req *http.Request){
  //hnd.Tpl.ExecuteTemplate(res,"pcap-analyzer.html",nil)
  http.Error(res, "An error occurred", http.StatusInternalServerError)
  return
}
