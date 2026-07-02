package sigma

import (
	"gopkg.in/yaml.v3"
)

func InferFileType(contents []byte) FileType {
	var fileType FileType
	if err := yaml.Unmarshal(contents, &fileType); err != nil {
		fileType = InvalidFile
	}
	return fileType
}

type FileType string

const (
	UnknownFile FileType = ""
	InvalidFile FileType = "invalid"
	RuleFile    FileType = "rule"
	ConfigFile  FileType = "config"
)

func (f *FileType) UnmarshalYAML(node *yaml.Node) error {
	// Check if there's a top-level key called "detection".
	// This is a required field in a Sigma rule but doesn't exist in a config.
	// node.Content alternates key/value pairs, so step by two and look at keys
	// only - a *value* that happens to be "detection" or "correlation" (e.g.
	// `title: correlation`) must not classify the file.
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		if key.Kind != yaml.ScalarNode {
			continue
		}
		switch key.Value {
		case "detection", "correlation":
			// Correlation rules have a `correlation` key instead of `detection`
			// but are still Sigma rule documents.
			*f = RuleFile
			return nil
		case "logsources":
			*f = ConfigFile
			return nil
		}
	}
	return nil
}
