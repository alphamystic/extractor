package handlers

import (
	"fmt"
	"strings"
	"io/ioutil"
	"html/template"
)

/*
var PAGES []{string}{}

func (hnd *Handler) LoadPages(){
	// read the whole Directory
	pages,err := ioutil.ReadDir(hnd.TemplatesDir + "pages/")
	if err != nil {
		return fmt.Errorf("Error reading body Directory: %q",err)
	}
	// For each, read the pages and index it with the name.
	for _, page := range pages {
		name,data
	}
}
*/
// Creates a whole new base template for serving
func (hnd *Handler) LoadBase() error {
	baseHTML, err := ioutil.ReadFile(hnd.TemplatesDir +"base.tmpl")
	if err != nil {
		return fmt.Errorf("Error loading base template: %q",err)
	}
	/*baseDash, err := ioutil.ReadFile(hnd.TemplatesDir + "base_dash.tmpl")
	if err != nil {
		return fmt.Errorf("Error loading base dash template: %q",err)
	}*/
	shortcuts,err := ioutil.ReadFile(hnd.TemplatesDir + "shortcuts.tmpl")
	if err != nil {
		return fmt.Errorf("Error loading header template: %q",err)
	}
	header, err := ioutil.ReadFile(hnd.TemplatesDir + "header.tmpl")
	if err != nil {
		return fmt.Errorf("Error loading header template: %q",err)
	}
	sidebar, err := ioutil.ReadFile(hnd.TemplatesDir + "sidebar.tmpl")
	if err != nil {
		return fmt.Errorf("Error loading sidebar template: %q",err)
	}
	notifications, err := ioutil.ReadFile(hnd.TemplatesDir + "notifications.tmpl")
	if err != nil {
		return  fmt.Errorf("Error loading footer template: %q",err)
	}

	/* Put this 2 into a work group
	combinedDash := strings.ReplaceAll(string(prflDash), "{{.HEADER}}", string(header))
	combinedDash = strings.ReplaceAll(combinedDash, "{{.SIDEBAR}}", string(sidebar))
	combinedDash = strings.ReplaceAll(combinedDash, "{{.FOOTER}}", string(footer))
	hnd.BaseDash = combinedDash

	combinedPfl := strings.ReplaceAll(string(baseDash), "{{.HEADER}}", string(header))
	combinedPfl = strings.ReplaceAll(combinedPfl, "{{.SIDEBAR}}", string(sidebar))
	combinedPfl = strings.ReplaceAll(combinedPfl, "{{.FOOTER}}", string(footer))
	hnd.BaseProfiler = combinedPfl*/

	// Replace placeholders in the base HTML with actual content
	combinedHTML := strings.ReplaceAll(string(baseHTML), "{{.HEADER}}", string(header))
	combinedHTML = strings.ReplaceAll(combinedHTML, "{{.SIDEBAR}}", string(sidebar))
	combinedHTML = strings.ReplaceAll(combinedHTML, "{{.NOTIFICATIONS}}", string(notifications))
	combinedHTML = strings.ReplaceAll(combinedHTML, "{{.FOOTER}}", string(shortcuts))
	hnd.Base = combinedHTML
	//var tpl = new(template.Template)
	var tpl = template.New("base")
	tpl,err = tpl.Parse(string(combinedHTML))
	if err != nil {
		return fmt.Errorf("Error parsing combined html to a template: %q",err)
	}
	hnd.Tpl = tpl
	return  nil
}

func (hnd *Handler) GetATemplate(name,templFile string) (*template.Template,error) {
	body,err := ioutil.ReadFile(hnd.TemplatesDir + "pages/" + templFile)
	if err != nil {
		return nil,fmt.Errorf("Error getting template %s: %q",templFile,err)
	}
	sTpl := strings.ReplaceAll(hnd.Base,"{{.BODY}}",string(body))
	var tpl = template.New(name)
	tpl,err = tpl.Parse(string(sTpl))
	if err != nil{
		return nil,fmt.Errorf("Error parsing body to template: %q",err)
	}
	return tpl,nil
}

func (hnd *Handler) GetDash(name,templFile string) (*template.Template,error) {
	body,err := ioutil.ReadFile(hnd.TemplatesDir + "pages/" + templFile)
	if err != nil {
		return nil,fmt.Errorf("Error getting template %s: %q",templFile,err)
	}
	sTpl := strings.ReplaceAll(hnd.BaseDash,"{{.BODY}}",string(body))
	var tpl = template.New(name)
	tpl,err = tpl.Parse(string(sTpl))
	if err != nil{
		return nil,fmt.Errorf("Error parsing body to template: %q",err)
	}
	return tpl,nil
}

func (hnd *Handler) GetProfiler(name,templFile string) (*template.Template,error) {
	body,err := ioutil.ReadFile(hnd.TemplatesDir + "pages/" + templFile)
	if err != nil {
		return nil,fmt.Errorf("Error getting template %s: %q",templFile,err)
	}
	sTpl := strings.ReplaceAll(hnd.BaseProfiler,"{{.BODY}}",string(body))
	var tpl = template.New(name)
	tpl,err = tpl.Parse(string(sTpl))
	if err != nil{
		return nil,fmt.Errorf("Error parsing body to template: %q",err)
	}
	return tpl,nil
}

func (hnd *Handler) CombineToBase(data string) string {
	newBase := strings.ReplaceAll(hnd.BaseDash,"{{.BODY}}",data)
	return newBase
}
