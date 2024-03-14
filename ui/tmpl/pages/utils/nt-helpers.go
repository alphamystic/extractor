//go:build windows
// +build windows

package utils

import (
  "os"
  "os/exec"
)

// stollen from https://github.com/mauri870/ransomware
func GetDrives() (letters []string) {
	for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		_, err := os.Open(string(drive) + ":\\")
		if err == nil {
			letters = append(letters, string(drive)+":\\")
		}
	}
	return
}

var RunExecutable = func(pathToExec string)(int,error){
  cmd := exec.Command(pathToExec)
  err := cmd.Start()
  if err != nil{
    return 0,err
  }
  return cmd.Process.Pid,nil
}
