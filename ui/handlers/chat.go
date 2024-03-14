package handlers

import (
  "fmt"
  "net/http"
  "github.com/alphamystic/extractor/lib/utils"
)

// add phishing link
func (hnd *Handler) Chat(res http.ResponseWriter, req *http.Request){
  tpl,err := hnd.GetATemplate("chat.tmpl","chat.tmpl")
  if err != nil{
    utils.Warning(fmt.Sprintf("%s",err))
    http.Error(res, "An error occurred", http.StatusInternalServerError)
  }
  tpl.ExecuteTemplate(res,"chat.tmpl",nil)
}
