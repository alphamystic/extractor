package definers

import (
  "github.com/alphamystic/extractor/lib/utils"
)

type YaraRule struct {
  YRId int
  IocID int
  Name string
  Meta []map[string]string
  Condition string
  Actions []map[string]string
  utils.TimeStamps
}

var RuleTemplate = `
rule {{ .RuleName }} {
	meta:
		description = "{{ .Description }}"
		author = "Your Name"
		reference = "Any relevant reference"

	strings:
		$string1 = "example_string" // Define strings or patterns to match

	condition:
		$string1 // Define the condition for the rule
}
`

/*
type MetaTags struct{
  RequiredModules
  Tags []string // ["Malbot","MiterTechnique"]
}
Name: "Suspicious_Malware",
        Meta: map[string]string{
            "author":   "John Doe",
            "date":     "2023-05-17",
            "severity": "High",
            "score" : "80",
            "rule_hash": "fsdfghjkl",
            "tags" : "["Malbot","MiterTechnique"]"
        },
        Condition: "($filetype == \"PE\") and ($filesize < 100KB)",
        Actions: []string{
            "Log(\"Suspicious file detected\")",
            "BlockConnection()",
        },
*/
