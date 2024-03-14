package handlers

import (
  "fmt"
  "net/http"
  "github.com/alphamystic/extractor/lib/utils"
)

func (hnd *Handler) CreateYaraRule(res http.ResponseWriter, req *http.Request){
  tpl,err := hnd.GetATemplate("create_yara_rule.tmpl","create_yara_rule.tmpl")
  if err != nil{
    utils.Warning(fmt.Sprintf("%s",err))
    http.Error(res, "An error occurred", http.StatusInternalServerError)
  }
  tpl.ExecuteTemplate(res,"create_yara_rule.tmpl",nil)
}


func (hnd *Handler) ListYaraRule(res http.ResponseWriter, req *http.Request){
  //hnd.Tpl.ExecuteTemplate(res,"calendar.html",nil)
  return
}

/*
func (hnd *Handler) Calender(res http.ResponseWriter, req *http.Request){
  //hnd.Tpl.ExecuteTemplate(res,"calendar.html",nil)
  http.Error(res, "An error occurred", http.StatusInternalServerError)
  return
}
*/
