package definers

import (
  "github.com/alphamystic/extractor/lib/utils"
)

type UserData struct {
  UserID string
  Role string
  Hash string
  Name string
  Email string
  Password string
  Verified bool
  Userhash string
  utils.TimeStamps
}
