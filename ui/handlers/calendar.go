package handlers

import(
  ///"fmt"
  "net/http"
)

func (hnd *Handler) Calender(res http.ResponseWriter, req *http.Request){
  //hnd.Tpl.ExecuteTemplate(res,"calendar.html",nil)
  http.Error(res, "An error occurred", http.StatusInternalServerError)
  return
}
