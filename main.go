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
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"sync"
	"time"

	"bytes"
	"regexp"

	"github.com/blablacar/acserver/dist"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

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

var (
	directory string
	username  string
	password  string

	uploadcounter int
	newuploadLock sync.Mutex
	uploads       map[int]*upload

	gpgpubkey = flag.String("pubkeys", "",
		"Path to gpg public keys images will be signed with")
	https = flag.Bool("https", false,
		"Whether or not to provide https URLs for meta discovery")
	port       = flag.Int("port", 3000, "The port to run the server on")
	serverName = flag.String("domain", "", "domain provided by discovery")
	unsigned   = flag.Bool("unsigned", false, "Ignore aci signature")

	imageFilePattern   = regexp.MustCompile(`^([a-z0-9_-]+)-([a-z0-9_\-\.]+)-([a-z0-9_]+)-([a-z0-9_]+).aci$`)
	hostAndNamePattern = regexp.MustCompile(`^([a-z0-9_\-.]+(?:\/[a-z0-9_\-.]+)*)\/([a-z0-9_-]+)$`)
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(os.Stderr,
		"acserver ACI_DIRECTORY USERNAME PASSWORD\n")
	fmt.Fprintf(os.Stderr, "Flags:\n")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()

	if len(args) != 3 {
		usage()
		return
	}

	if gpgpubkey == nil {
		fmt.Fprintf(os.Stderr, "internal error: gpgpubkey is nil")
		return
	}

	if https == nil {
		fmt.Fprintf(os.Stderr, "internal error: https is nil")
		return
	}

	if port == nil {
		fmt.Fprintf(os.Stderr, "internal error: port is nil")
		return
	}

	directory = args[0]
	username = args[1]
	password = args[2]

	os.RemoveAll(path.Join(directory, "tmp"))
	err := os.MkdirAll(path.Join(directory, "tmp"), 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		return
	}

	uploads = make(map[int]*upload)

	authHandler := func(h http.HandlerFunc) http.Handler {
		return authBasic(username, password, h)
	}

	r := mux.NewRouter()
	r.HandleFunc("/", renderListOfACIs)
	r.HandleFunc("/pubkeys.gpg", getPubkeys)
	r.Handle("/{image}/startupload", authHandler(initiateUpload))
	r.Handle("/manifest/{num}", authHandler(uploadManifest))
	r.Handle("/signature/{num}", authHandler(receiveUpload(tmpSigPath, gotSig)))
	r.Handle("/aci/{num}", authHandler(receiveUpload(tmpACIPath, gotACI)))
	r.Handle("/complete/{num}", authHandler(completeUpload))
	r.HandleFunc("/find", find)

	r.NotFoundHandler = http.FileServer(http.Dir(directory))

	h := handlers.LoggingHandler(os.Stderr, r)

	addr := ":" + strconv.Itoa(*port)
	log.Println("Listening on", addr)
	log.Fatal(http.ListenAndServe(addr, h))
}

func find(w http.ResponseWriter, req *http.Request) {
	var url bytes.Buffer

	os := req.URL.Query().Get("os")
	arch := req.URL.Query().Get("arch")
	ext := req.URL.Query().Get("ext")
	version := req.URL.Query().Get("version")
	hostAndName := hostAndNamePattern.FindStringSubmatch(req.URL.Query().Get("name"))
	if len(hostAndName) != 3 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	url.WriteString("http")
	if *https {
		url.WriteRune('s')
	}
	url.WriteString("://")
	url.WriteString(hostname(req))
	url.WriteRune('/')
	url.WriteString(hostAndName[1])
	url.WriteRune('/')
	url.WriteString(hostAndName[2])
	url.WriteRune('/')
	url.WriteString(hostAndName[2])
	url.WriteRune('-')
	url.WriteString(version)
	url.WriteRune('-')
	url.WriteString(os)
	url.WriteRune('-')
	url.WriteString(arch)
	url.WriteRune('.')
	url.WriteString(ext)

	http.Redirect(w, req, url.String(), http.StatusFound)
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

// The root page. Builds a human-readable list of what ACIs are available,
// and also provides the meta tags for the server for meta discovery.
func renderListOfACIs(w http.ResponseWriter, req *http.Request) {
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
	acis, err := listACIs(req)
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
		ServerName: hostname(req),
		ACIs:       acis,
		HTTPS:      *https,
	})

	if err != nil {
		fmt.Fprintf(w, fmt.Sprintf("%v", err))
	}
}

func hostname(req *http.Request) string {
	if *serverName != "" {
		return *serverName
	}
	return req.Host
}

// Sends the gpg public keys specified via the flag to the client
func getPubkeys(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if *gpgpubkey == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	file, err := os.Open(*gpgpubkey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening gpg public key: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer file.Close()
	_, err = io.Copy(w, file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading gpg public key: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func initiateUpload(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	image := mux.Vars(req)["image"]
	if image == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	uploadNum := strconv.Itoa(newUpload(image))

	var prefix string
	if *https {
		prefix = "https://" + hostname(req)
	} else {
		prefix = "http://" + hostname(req)
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

func uploadManifest(w http.ResponseWriter, req *http.Request) {
	if req.Method != "PUT" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	num, err := strconv.Atoi(mux.Vars(req)["num"])
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	err = gotMan(num)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(os.Stderr, "%v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func receiveUpload(genDst func(int) string, marksuccess func(int) error) func(http.ResponseWriter, *http.Request) {
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

		up := getUpload(num)
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

func tmpSigPath(num int) string {
	return path.Join(directory, "tmp", strconv.Itoa(num)+".asc")
}

func tmpACIPath(num int) string {
	return path.Join(directory, "tmp", strconv.Itoa(num))
}

func completeUpload(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	num, err := strconv.Atoi(mux.Vars(req)["num"])
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	up := getUpload(num)
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
		reportFailure(num, w, "client reported failure", msg.Reason)
		return
	}

	if !up.GotMan {
		reportFailure(num, w, "manifest wasn't uploaded", msg.Reason)
		return
	}

	if !*unsigned && !up.GotSig {
		reportFailure(num, w, "signature wasn't uploaded", msg.Reason)
		return
	}

	if !up.GotACI {
		reportFailure(num, w, "ACI wasn't uploaded", msg.Reason)
		return
	}

	//TODO: image verification here

	err = finishUpload(num, req)
	if err != nil {
		reportFailure(num, w, "Internal Server Error", msg.Reason)
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

func reportFailure(num int, w http.ResponseWriter, msg, clientmsg string) error {
	err := abortUpload(num)
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

func abortUpload(num int) error {
	newuploadLock.Lock()
	delete(uploads, num)
	newuploadLock.Unlock()

	tmpaci := path.Join(directory, "tmp", strconv.Itoa(num))
	_, err := os.Stat(tmpaci)
	if err == nil {
		err = os.Remove(tmpaci)
		if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	tmpsig := path.Join(directory, "tmp", strconv.Itoa(num)+".asc")
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

func finishUpload(num int, req *http.Request) error {
	newuploadLock.Lock()
	up, ok := uploads[num]
	if ok {
		delete(uploads, num)
	}
	newuploadLock.Unlock()
	if !ok {
		return fmt.Errorf("no such upload: %d", num)
	}

	res := imageFilePattern.FindStringSubmatch(up.Image)
	targetPath := path.Join(directory, hostname(req), res[1])
	if err := os.MkdirAll(targetPath, 0755); err != nil {
		return err
	}

	err := os.Rename(path.Join(directory, "tmp", strconv.Itoa(num)), path.Join(targetPath, up.Image))
	if err != nil {
		return err
	}

	tmpsig := path.Join(directory, "tmp", strconv.Itoa(num)+".asc")
	if _, err := os.Stat(tmpsig); err == nil {
		err = os.Rename(tmpsig, path.Join(directory, up.Image+".asc"))
		if err != nil {
			return err
		}
	}

	return nil
}

func newUpload(image string) int {
	newuploadLock.Lock()
	uploadcounter++
	uploads[uploadcounter] = &upload{
		Started: time.Now(),
		Image:   image,
	}
	newuploadLock.Unlock()
	return uploadcounter
}

func getUpload(num int) *upload {
	var up *upload
	newuploadLock.Lock()
	up, ok := uploads[num]
	newuploadLock.Unlock()
	if !ok {
		return nil
	}
	return up
}

func gotSig(num int) error {
	newuploadLock.Lock()
	_, ok := uploads[num]
	if ok {
		uploads[num].GotSig = true
	}
	newuploadLock.Unlock()
	if !ok {
		return fmt.Errorf("no such upload: %d", num)
	}
	return nil
}

func gotACI(num int) error {
	newuploadLock.Lock()
	_, ok := uploads[num]
	if ok {
		uploads[num].GotACI = true
	}
	newuploadLock.Unlock()
	if !ok {
		return fmt.Errorf("no such upload: %d", num)
	}
	return nil
}

func gotMan(num int) error {
	newuploadLock.Lock()
	_, ok := uploads[num]
	if ok {
		uploads[num].GotMan = true
	}
	newuploadLock.Unlock()
	if !ok {
		return fmt.Errorf("no such upload: %d", num)
	}
	return nil
}

func listACIs(req *http.Request) ([]aci, error) {
	rootPath := path.Join(directory, hostname(req))
	dirs, err := ioutil.ReadDir(rootPath)
	if err != nil {
		return nil, err
	}

	var acis []aci
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}

		aciDir := path.Join(rootPath, dir.Name())
		files, err := ioutil.ReadDir(aciDir)
		if err != nil {
			return nil, err
		}

		aci := aci{Name: dir.Name()}

		for _, file := range files {
			fileParts := imageFilePattern.FindStringSubmatch(file.Name())
			if len(fileParts) != 5 {
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
				Version: fileParts[2],
				OS:      fileParts[3],
				Arch:    fileParts[4],
				Signed:  signed,
				LastMod: file.ModTime().Format("Mon Jan 2 15:04:05 -0700 MST 2006"),
			}
			aci.Details = append(aci.Details, details)
		}

		acis = append(acis, aci)
	}

	return acis, nil
}
