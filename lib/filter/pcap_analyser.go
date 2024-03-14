package filter


var report = `
Total number of packets: {{.NumberOfPackets}}
Protocols Found:
  {{with .ProtocolsFound}}
  {{range .}}
    Name: {{.Name}}
    Number of packets: {{.Count}}
  {{end}}
  {{end}}
Files found:
  {{with .FilesFound}}
  {{range .}}
    File Name: {{.Name}}
  {{end}}
  {{end}}
`

type ProtocolFound struct {
  Name string
  Count int
}

type ProtocolsFound struct {
  PF []ProtocolFound
}
