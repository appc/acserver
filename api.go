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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"sync"
	"text/template"
	"time"

	"github.com/appc/acserver/dist"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

type ACApi struct {
	ServerName string
	Port       int
	Https      bool
	Username   string
	Password   string

	storage       *ACStorage
	uploadcounter int
	newuploadLock sync.Mutex
	uploads       map[int]*upload
	authHandler   func(h http.HandlerFunc) http.Handler
}

func (a *ACApi) init(storage *ACStorage) error {
	a.storage = storage
	if a.Port == 0 {
		a.Port = 3000
		fmt.Fprintf(os.Stderr, "No api port set, using default: %d\n", a.Port)
	}
	if a.Username == "" {
		fmt.Fprintf(os.Stderr, "No username set, security is disabled to push aci\n")
		a.authHandler = func(h http.HandlerFunc) http.Handler {
			return authInsecure(h)
		}
	} else {
		a.authHandler = func(h http.HandlerFunc) http.Handler {
			return authBasic(a.Username, a.Password, h)
		}
	}

	a.uploads = make(map[int]*upload)
	return nil
}

func (a ACApi) Start() {
	r := mux.NewRouter()
	r.HandleFunc("/", a.renderListOfACIs)
	r.Handle("/{image}/startupload", a.authHandler(a.initiateUpload))
	r.Handle("/manifest/{num}", a.authHandler(a.uploadManifest))
	r.Handle("/signature/{num}", a.authHandler(a.receiveUpload(a.storage.tmpSigPath, a.gotSig)))
	r.Handle("/aci/{num}", a.authHandler(a.receiveUpload(a.storage.tmpACIPath, a.gotACI)))
	r.Handle("/complete/{num}", a.authHandler(a.completeUpload))
	r.HandleFunc("/find", a.find)

	r.NotFoundHandler = http.FileServer(http.Dir(a.storage.RootPath))

	h := handlers.LoggingHandler(os.Stderr, r)

	addr := ":" + strconv.Itoa(a.Port)
	log.Println("Listening on", addr)
	log.Fatal(http.ListenAndServe(addr, h))
}

func (a ACApi) find(w http.ResponseWriter, req *http.Request) {
	var url bytes.Buffer

	aos := req.URL.Query().Get("os")
	arch := req.URL.Query().Get("arch")
	ext := req.URL.Query().Get("ext")
	version := req.URL.Query().Get("version")
	hostAndName := hostAndNamePattern.FindStringSubmatch(req.URL.Query().Get("name"))
	if len(hostAndName) != 3 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if version == "latest" {
		rootPath := path.Join(a.storage.RootPath, hostAndName[1])
		info, err := os.Stat(path.Join(rootPath, hostAndName[2]))
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		aci, err := listAci(rootPath, info)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(os.Stderr, "%v", err)
			return
		} else if aci == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		for _, detail := range aci.Details {
			if detail.OS != aos || detail.Arch != arch {
				continue
			}
			if version == "latest" || Version(detail.Version).GreaterThan(Version(version)) {
				version = detail.Version
			}
		}
	}

	url.WriteString("http")
	if a.Https {
		url.WriteRune('s')
	}
	url.WriteString("://")
	url.WriteString(a.hostname(req))
	url.WriteRune('/')
	url.WriteString(hostAndName[1])
	url.WriteRune('/')
	url.WriteString(hostAndName[2])
	url.WriteRune('/')
	url.WriteString(hostAndName[2])
	url.WriteRune('-')
	url.WriteString(version)
	url.WriteRune('-')
	url.WriteString(aos)
	url.WriteRune('-')
	url.WriteString(arch)
	url.WriteRune('.')
	url.WriteString(ext)

	http.Redirect(w, req, url.String(), http.StatusFound)
}

func authInsecure(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	}
}

func authBasic(user, pass string, h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqUser, reqPass, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "No authorization provided", http.StatusUnauthorized)
			return
		}

		if reqUser != user || reqPass != pass {
			http.Error(w, "Incorrect username/password basic auth provided ", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	}
}

type initiateDetails struct {
	ACIPushVersion string `json:"aci_push_version"`
	Multipart      bool   `json:"multipart"`
	ManifestURL    string `json:"upload_manifest_url"`
	SignatureURL   string `json:"upload_signature_url"`
	ACIURL         string `json:"upload_aci_url"`
	CompletedURL   string `json:"completed_url"`
}

type completeMsg struct {
	Success      bool   `json:"success"`
	Reason       string `json:"reason,omitempty"`
	ServerReason string `json:"server_reason,omitempty"`
}

type upload struct {
	Started time.Time
	Image   string
	GotSig  bool
	GotACI  bool
	GotMan  bool
}

// The root page. Builds a human-readable list of what ACIs are available,
// and also provides the meta tags for the server for meta discovery.
func (a *ACApi) renderListOfACIs(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	content, err := dist.Asset("templates/index.html")
	if err != nil {
		fmt.Fprintf(w, fmt.Sprintf("%v", err))
	}
	t, err := template.New("index").Parse(string(content))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, fmt.Sprintf("%v", err))
		return
	}
	acis, err := a.storage.ListACIs(a.hostname(req))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, fmt.Sprintf("%v", err))
		return
	}
	err = t.Execute(w, struct {
		ServerName string
		ACIs       []aci
		HTTPS      bool
	}{
		ServerName: a.hostname(req),
		ACIs:       acis,
		HTTPS:      a.Https,
	})

	if err != nil {
		fmt.Fprintf(w, fmt.Sprintf("%v", err))
	}
}

func (a *ACApi) hostname(req *http.Request) string {
	if a.ServerName != "" {
		return a.ServerName
	}
	return req.Host
}

func (a *ACApi) initiateUpload(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	image := mux.Vars(req)["image"]
	if image == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	uploadNum := strconv.Itoa(a.newUpload(image))

	var prefix string
	if a.Https {
		prefix = "https://" + a.hostname(req)
	} else {
		prefix = "http://" + a.hostname(req)
	}

	deets := initiateDetails{
		ACIPushVersion: "0.0.1",
		Multipart:      false,
		ManifestURL:    prefix + "/manifest/" + uploadNum,
		SignatureURL:   prefix + "/signature/" + uploadNum,
		ACIURL:         prefix + "/aci/" + uploadNum,
		CompletedURL:   prefix + "/complete/" + uploadNum,
	}

	blob, err := json.Marshal(deets)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(os.Stderr, fmt.Sprintf("%v", err))
		return
	}

	_, err = w.Write(blob)
	if err != nil {
		fmt.Fprintf(os.Stderr, fmt.Sprintf("%v", err))
		return
	}
}

func (a *ACApi) uploadManifest(w http.ResponseWriter, req *http.Request) {
	if req.Method != "PUT" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	num, err := strconv.Atoi(mux.Vars(req)["num"])
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	err = a.gotMan(num)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(os.Stderr, "%v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *ACApi) receiveUpload(genDst func(int) string, marksuccess func(int) error) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "PUT" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		num, err := strconv.Atoi(mux.Vars(req)["num"])
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		up := a.getUpload(num)
		if up == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		_, err = os.Stat(up.Image)
		if err == nil {
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte("item already uploaded"))
			return
		} else if !os.IsNotExist(err) {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(os.Stderr, "%v", err)
			return
		}

		aci, err := os.OpenFile(genDst(num),
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(os.Stderr, "%v", err)
			return
		}
		defer aci.Close()

		_, err = io.Copy(aci, req.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(os.Stderr, "%v", err)
			return
		}

		err = marksuccess(num)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(os.Stderr, "%v", err)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func (a *ACApi) completeUpload(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	num, err := strconv.Atoi(mux.Vars(req)["num"])
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	up := a.getUpload(num)
	if up == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(os.Stderr, "body: %s\n", string(body))

	msg := completeMsg{}
	err = json.Unmarshal(body, &msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error unmarshaling json: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !msg.Success {
		a.reportFailure(num, w, "client reported failure", msg.Reason)
		return
	}

	if !up.GotMan {
		a.reportFailure(num, w, "manifest wasn't uploaded", msg.Reason)
		return
	}

	if !*a.storage.Unsigned && !up.GotSig {
		a.reportFailure(num, w, "signature wasn't uploaded", msg.Reason)
		return
	}

	if !up.GotACI {
		a.reportFailure(num, w, "ACI wasn't uploaded", msg.Reason)
		return
	}

	//TODO: image verification here

	err = a.finishUpload(num, req)
	if err != nil {
		a.reportFailure(num, w, "Internal Server Error", msg.Reason)
		return
	}

	succmsg := completeMsg{
		Success: true,
	}

	blob, err := json.Marshal(succmsg)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = w.Write(blob)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	return
}

func (a *ACApi) reportFailure(num int, w http.ResponseWriter, msg, clientmsg string) error {
	err := a.abortUpload(num)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	failmsg := completeMsg{
		Success:      false,
		Reason:       clientmsg,
		ServerReason: msg,
	}

	blob, err := json.Marshal(failmsg)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	_, err = w.Write(blob)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}
	return nil
}

func (a *ACApi) abortUpload(num int) error {
	a.newuploadLock.Lock()
	delete(a.uploads, num)
	a.newuploadLock.Unlock()

	tmpaci := path.Join(a.storage.RootPath, "tmp", strconv.Itoa(num)) // TODO rootPath is unknown to API
	_, err := os.Stat(tmpaci)
	if err == nil {
		err = os.Remove(tmpaci)
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	tmpsig := path.Join(a.storage.RootPath, "tmp", strconv.Itoa(num)+".asc")
	_, err = os.Stat(tmpsig)
	if err == nil {
		err = os.Remove(tmpsig)
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	return nil
}

func (a *ACApi) finishUpload(num int, req *http.Request) error {
	a.newuploadLock.Lock()
	_, ok := a.uploads[num]
	if ok {
		delete(a.uploads, num)
	}
	a.newuploadLock.Unlock()
	if !ok {
		return fmt.Errorf("no such upload: %d", num)
	}

	finalPath, filename, err := a.storage.ComputeFinalPathAndFile(num)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(finalPath, 0755); err != nil {
		return err
	}

	err = os.Rename(path.Join(a.storage.RootPath, "tmp", strconv.Itoa(num)), path.Join(finalPath, filename))
	if err != nil {
		return err
	}

	tmpsig := path.Join(a.storage.RootPath, "tmp", strconv.Itoa(num)+".asc")
	if _, err := os.Stat(tmpsig); err == nil {
		err = os.Rename(tmpsig, path.Join(finalPath, filename+".asc"))
		if err != nil {
			return err
		}
	}

	return nil
}

func (a *ACApi) newUpload(image string) int {
	a.newuploadLock.Lock()
	a.uploadcounter++
	a.uploads[a.uploadcounter] = &upload{
		Started: time.Now(),
		Image:   image,
	}
	a.newuploadLock.Unlock()
	return a.uploadcounter
}

func (a *ACApi) getUpload(num int) *upload {
	var up *upload
	a.newuploadLock.Lock()
	up, ok := a.uploads[num]
	a.newuploadLock.Unlock()
	if !ok {
		return nil
	}
	return up
}

func (a *ACApi) gotSig(num int) error {
	a.newuploadLock.Lock()
	_, ok := a.uploads[num]
	if ok {
		a.uploads[num].GotSig = true
	}
	a.newuploadLock.Unlock()
	if !ok {
		return fmt.Errorf("no such upload: %d", num)
	}
	return nil
}

func (a *ACApi) gotACI(num int) error {
	a.newuploadLock.Lock()
	_, ok := a.uploads[num]
	if ok {
		a.uploads[num].GotACI = true
	}
	a.newuploadLock.Unlock()
	if !ok {
		return fmt.Errorf("no such upload: %d", num)
	}
	return nil
}

func (a *ACApi) gotMan(num int) error {
	a.newuploadLock.Lock()
	_, ok := a.uploads[num]
	if ok {
		a.uploads[num].GotMan = true
	}
	a.newuploadLock.Unlock()
	if !ok {
		return fmt.Errorf("no such upload: %d", num)
	}
	return nil
}
