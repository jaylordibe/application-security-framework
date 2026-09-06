package main

import (
	"os"
	"path/filepath"
)

func osMkdirAll(root, rel string) error {
	return os.MkdirAll(filepath.Dir(filepath.Join(root, rel)), 0o700)
}

func osWriteFile(root, rel, content string) error {
	return os.WriteFile(filepath.Join(root, rel), []byte(content), 0o600)
}
