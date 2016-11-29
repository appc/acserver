// Copyright 2015 The appc Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	appcaci "github.com/appc/spec/aci"
	"github.com/appc/spec/schema"
)

var (
	versionOsArchPattern = regexp.MustCompile(`^-([a-z0-9_\-\.]+)-([a-z0-9_]+)-([a-z0-9_]+).aci$`)
	hostAndNamePattern   = regexp.MustCompile(`^([a-z0-9_\-.]+(?:\/[a-z0-9_\-.]+)*)\/([a-z0-9_-]+)$`)
)

type ACStorage struct {
	RootPath string
	Unsigned *bool
}

func (s *ACStorage) init() error {
	if s.RootPath == "" {
		s.RootPath = "/tmp/acis"
		fmt.Fprintf(os.Stderr, "No storage rootPath set, using default: %s\n", s.RootPath)
	}
	if s.Unsigned == nil {
		unsigned := true
		s.Unsigned = &unsigned
	}
	return nil
}

func (s *ACStorage) start() {
	os.RemoveAll(path.Join(s.RootPath, "tmp"))
	err := os.MkdirAll(path.Join(s.RootPath, "tmp"), 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		return
	}
}

type aci struct {
	Name    string
	Details []acidetails
}

type acidetails struct {
	Version string
	OS      string
	Arch    string
	Signed  bool
	LastMod string
}

func (s *ACStorage) tmpSigPath(num int) string {
	return path.Join(s.RootPath, "tmp", strconv.Itoa(num)+".asc")
}

func (s *ACStorage) tmpACIPath(num int) string {
	return path.Join(s.RootPath, "tmp", strconv.Itoa(num))
}

func extractManifest(aciPath string) (*schema.ImageManifest, error) {
	aciFile, err := os.Open(aciPath)
	if err != nil {
		return nil, err
	}
	defer aciFile.Close()

	manifest, err := appcaci.ManifestFromImage(aciFile)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (s *ACStorage) ComputeFinalPathAndFile(num int) (string, string, error) { // TODO num is unknown for storage
	manifest, err := extractManifest(path.Join(s.RootPath, "tmp", strconv.Itoa(num)))
	if err != nil {
		return "", "", err
	}

	res := hostAndNamePattern.FindStringSubmatch(string(manifest.Name))
	version, ok := manifest.GetLabel("version")
	if !ok {
		return "", "", fmt.Errorf("version not found in aci manifest")
	}
	os, ok := manifest.GetLabel("os")
	if !ok {
		return "", "", fmt.Errorf("os not found in aci manifest")
	}
	arch, ok := manifest.GetLabel("arch")
	if !ok {
		return "", "", fmt.Errorf("arch not found in aci manifest")
	}

	targetPath := path.Join(s.RootPath, res[1], res[2])
	filename := res[2] + "-" + version + "-" + os + "-" + arch + ".aci"
	return targetPath, filename, nil
}

func (s *ACStorage) ListACIs(hostname string) ([]aci, error) {
	rootPath := path.Join(s.RootPath, hostname)
	dirs, err := ioutil.ReadDir(rootPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Aci directory not found : %v\n", err)
		return []aci{}, nil
	}

	var acis []aci
	for _, dir := range dirs {
		aci, err := listAci(rootPath, dir)
		if err != nil {
			return nil, err
		}
		if aci != nil {
			acis = append(acis, *aci)
		}
	}

	return acis, nil
}

func listAci(rootPath string, dir os.FileInfo) (*aci, error) {
	if !dir.IsDir() {
		return nil, nil
	}

	aciDir := path.Join(rootPath, dir.Name())

	files, err := ioutil.ReadDir(aciDir)
	if err != nil {
		return nil, err
	}

	aci := &aci{Name: dir.Name()}

	for _, file := range files {
		versionOsArch := strings.TrimPrefix(file.Name(), path.Base(aciDir))
		fileParts := versionOsArchPattern.FindStringSubmatch(versionOsArch)
		if len(fileParts) != 4 {
			continue
		}

		var signed bool

		_, err := os.Stat(path.Join(aciDir, file.Name()+".asc"))
		if err == nil {
			signed = true
		} else if os.IsNotExist(err) {
			signed = false
		} else {
			return nil, err
		}

		details := acidetails{
			Version: fileParts[1],
			OS:      fileParts[2],
			Arch:    fileParts[3],
			Signed:  signed,
			LastMod: file.ModTime().Format("Mon Jan 2 15:04:05 -0700 MST 2006"),
		}
		aci.Details = append(aci.Details, details)
	}
	return aci, nil
}
