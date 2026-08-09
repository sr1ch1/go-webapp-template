package web

import (
	"io/fs"
	"testing"
)

func TestFSEmbedsTemplatesAndStatic(t *testing.T) {
	for _, dir := range []string{"templates", "static"} {
		entries, err := fs.ReadDir(FS, dir)
		if err != nil {
			t.Fatalf("ReadDir(%q): %v", dir, err)
		}
		if len(entries) == 0 {
			t.Errorf("ReadDir(%q) found no entries, want at least one", dir)
		}
	}
}

func TestFSKnownAssets(t *testing.T) {
	for _, name := range []string{
		"templates/home.html",
		"static/app.css",
		"static/app.js",
	} {
		info, err := fs.Stat(FS, name)
		if err != nil {
			t.Errorf("Stat(%q): %v", name, err)
			continue
		}
		if info.IsDir() {
			t.Errorf("Stat(%q) reports a directory, want a file", name)
		}
		if info.Size() == 0 {
			t.Errorf("Stat(%q) size = 0, want a non-empty file", name)
		}
	}
}

func TestFSGlob(t *testing.T) {
	for _, pattern := range []string{"templates/*", "static/*"} {
		matches, err := fs.Glob(FS, pattern)
		if err != nil {
			t.Fatalf("Glob(%q): %v", pattern, err)
		}
		if len(matches) == 0 {
			t.Errorf("Glob(%q) found no matches, want at least one", pattern)
		}
	}
}
