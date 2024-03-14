package definers

import (
  "errors"
)

var (
  USP = errors.New("UnSurported Protocol")
  NPF = errors.New("No Surported Protocol was found.")
  UserNotLoggedIn = errors.New("User Not Logged in.")
  NoCLaims = errors.New("No Claims")
)
