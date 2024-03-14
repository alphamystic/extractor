package definers

type FileExtract struct {
  Name string
  Hash string
  FileTyste string // create a data type for this
  Body []byte
  Location string
}


/*
- SHA256 hash: 3a950d7e6736f17c3df90844c76d934dc66c17ec76841a4ad58de07af7955f0f
- File size: 1,566,208 bytes
- File type: MSI Installer
- File location: \\95.164.3[.]171@80\share\cisa.msi


type TrafficLog struct {
  Date/Time
  IP address
  Port  Host
  Info
}
*/
