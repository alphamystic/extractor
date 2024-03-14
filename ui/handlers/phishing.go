package handlers

import (
  "fmt"
  "net/http"
  "github.com/alphamystic/extractor/lib/utils"
)

// add phishing link
func (hnd *Handler) AddPL(res http.ResponseWriter, req *http.Request){
  tpl,err := hnd.GetATemplate("create_yara_rule.tmpl","create_yara_rule.tmpl")
  if err != nil{
    utils.Warning(fmt.Sprintf("%s",err))
    http.Error(res, "An error occurred", http.StatusInternalServerError)
  }
  tpl.ExecuteTemplate(res,"create_yara_rule.tmpl",nil)
}
