package handlers

import (
  "fmt"
  //"log"
  "time"
  "net/http"
  "database/sql"
  "html/template"
  "github.com/golang-jwt/jwt/v5"
  "github.com/alphamystic/extractor/lib/utils"
  dfn"github.com/alphamystic/extractor/lib/definers"
  "github.com/gorilla/sessions"
)
// go get -u github.com/golang-jwt/jwt/v5
type PFL map[string]interface{}

var now = time.Now()
var currentTime = now.Format("2006-01-02 15:04:05")

var Registration bool

var (
  test = false
  UniversalKey = "loiuixghjpou98y7t6txcvbiuoiugyftcvbno98igtfxcfgvbioiuyft"//use this to encrypt strings/ids
)

type ErrorPage struct {
  ErrorCode int
  Message string
  Back string
}

type Handler struct {
  Tpl *template.Template
  Store *sessions.CookieStore
  Dbs *sql.DB
  RL *utils.RequestLogger
  ShutdownChan,DoneChan chan bool // channels to write into
  Base,BaseDash,BaseProfiler string // the base template
  TemplatesDir string // templates directory
}

// Initiates new handler
func NewHandler(db_connection *sql.DB, shutdownCh chan bool, doneCh chan bool,rl *utils.RequestLogger) (*Handler,error) {
  /*tpl,err := template.ParseGlob("./moja/ui/templates/*.html")
  tpl,err := template.ParseGlob("./moja/ui/tmpl/*.tmpl")
  if err != nil{
    utils.Warning("[-]  Failed to load templates.")
    return nil,fmt.Errorf("[-]  This is not good like: ",err)
  }
  */
  var hnd = new(Handler)
  hnd.Store = sessions.NewCookieStore([]byte(utils.RandNoLetter(30)))
  hnd.Dbs = db_connection
  hnd.ShutdownChan = shutdownCh
  hnd.DoneChan = doneCh
  hnd.RL = rl
  hnd.TemplatesDir = "./ui/tmpl/"
  err := hnd.LoadBase()
  if err != nil {
    utils.Warning("[-]  Failed to load templates.")
    return nil,err
  }
  fmt.Println("[+]  Loaded all templates.")
  utils.PrintTextInASpecificColorInBold("white",fmt.Sprintf(" Starting Profiler server at: %s",currentTime))
  // create db configurations
  return hnd,nil
}


func (hnd *Handler) GenerateJWT(ud *dfn.UserData) (string,error) {
  expTime := time.Now().Add(time.Hour * 72)
  token := jwt.NewWithClaims(jwt.SigningMethodHS256,jwt.MapClaims{
    "ud": ud,
    "exp": expTime.Unix(),
  })
  sighnedToken,err := token.SignedString(hnd.Store)
  if err != nil {
    return "",fmt.Errorf("Error signing token: %q",err)
  }
  return sighnedToken,nil
}


func (hnd *Handler) GetUDFromToken(req *http.Request) (*dfn.UserData,error) {
  session,_ := hnd.Store.Get(req,"cookie")
  cookie,ok := session.Values["token"].(string)
  if !ok {
    return nil,dfn.UserNotLoggedIn
  }
  // @TODO add functionality to check expiry for a jwt token and save it
  token,err := jwt.Parse(cookie,func(tkn *jwt.Token)(interface{},error){
    if tkn.Method != jwt.SigningMethodHS256{
      return nil,fmt.Errorf("Unexepcted signing method: %v",tkn.Header["alg"])
    }
    return nil,fmt.Errorf("Some error I also do not know what it is.")
  })
  if err != nil {
    return nil,fmt.Errorf("Signing error. %q",err)
  }
  if claims,ok := token.Claims.(jwt.MapClaims); ok &&  token.Valid {
    if runtimeMap,ok := claims["ud"].(map[string]interface{}); ok {
      return &dfn.UserData {
        UserID: runtimeMap["UserId"].(string),
        Role: runtimeMap["Role"].(string),
        Hash: runtimeMap["Hash"].(string),
      },nil
    }
  }
  return nil,dfn.NoCLaims
}
