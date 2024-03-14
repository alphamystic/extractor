package handlers

import(
  "fmt"
  "net/http"
  "github.com/alphamystic/extractor/lib/utils"
)

func (hnd *Handler) Blank(res http.ResponseWriter, req *http.Request){
  //hnd.Tpl.ExecuteTemplate(res,"blank.html",nil)
  //fmt.Println("Running blank")
  http.Error(res, "An error occurred", http.StatusInternalServerError)
  return
}

func (hnd *Handler) Test(res http.ResponseWriter, req *http.Request) {
  tpl,err := hnd.GetATemplate("body","blank.tmpl")
  if err != nil{
    utils.Warning(fmt.Sprintf("%s",err))
    http.Error(res, "An error occurred", http.StatusInternalServerError)
  }
  tpl.ExecuteTemplate(res,"body",nil)
  fmt.Println("Error is nil page should be served")
}

/*
Generate the string
Return template.New
Place the data into the template and serve it

/*
So I want to serve a bunch of templates by combining them using text templates:
  Header
    Notifications
  Sidebar
  Body
  Footer


given I have 3 files
file 1
This is File 1
{{.DataForFile1}}

file 2
this is file 2
{{.DataForFIle2}}

file 3
This is file 3
{{.DataForFile3}}

how can I add data rather combine them to the base Html File
<html>
<head>
</head>
<body>
file 1
file 2
file 3
</body>
</html>
*/
