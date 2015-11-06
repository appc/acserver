package auth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/appc/acserver/Godeps/_workspace/src/github.com/codegangsta/negroni"
)

func Test_BasicAuth(t *testing.T) {
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("foo:bar"))

	h := http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte("hello"))
	})
	m := negroni.New()
	m.Use(Basic("foo", "bar"))
	m.UseHandler(h)

	r, _ := http.NewRequest("GET", "foo", nil)
	recorder := httptest.NewRecorder()
	m.ServeHTTP(recorder, r)

	if recorder.Code != 401 {
		t.Error("Response not 401")
	}

	respBody := recorder.Body.String()
	if respBody == "hello" {
		t.Error("Auth block failed")
	}

	recorder = httptest.NewRecorder()
	r.Header.Set("Authorization", auth)
	m.ServeHTTP(recorder, r)

	if recorder.Code == 401 {
		t.Error("Response is 401")
	}

	if recorder.Body.String() != "hello" {
		t.Error("Auth failed, got: ", recorder.Body.String())
	}
}

type MockDataStore struct {
	HashedPassword []byte
}

func (ds *MockDataStore) Get(key string) ([]byte, bool) {
	return ds.HashedPassword, true
}

func Test_CacheBasic(t *testing.T) {
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("foo:bar"))
	invalidAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("foo:barbar"))
	hashedPassword, err := Hash("bar")
	if err != nil {
		t.Error("Hashing password failed")
	}
	dataStore := &MockDataStore{hashedPassword}

	h := http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.Write([]byte("hello"))
	})
	cacheExpireTime := 500 * time.Millisecond
	cachePurseTime := 200 * time.Millisecond
	m := negroni.New()
	m.Use(CacheBasic(dataStore, cacheExpireTime, cachePurseTime))
	m.UseHandler(h)

	// Test request fails without credential.
	r, _ := http.NewRequest("GET", "foo", nil)
	recorder := httptest.NewRecorder()
	m.ServeHTTP(recorder, r)

	if recorder.Code != 401 {
		t.Error("Response not 401")
	}

	respBody := recorder.Body.String()
	if respBody == "hello" {
		t.Error("Auth block failed")
	}

	// Test request succeeds with valid credential.
	r.Header.Set("Authorization", auth)
	recorder = httptest.NewRecorder()
	m.ServeHTTP(recorder, r)

	if recorder.Code == 401 {
		t.Error("Response is 401")
	}

	if recorder.Body.String() != "hello" {
		t.Error("Auth failed, got: ", recorder.Body.String())
	}

	// Test request fails with invalid credential.
	r.Header.Set("Authorization", invalidAuth)
	recorder = httptest.NewRecorder()
	m.ServeHTTP(recorder, r)

	if recorder.Code != 401 {
		t.Error("Response not 401")
	}

	respBody = recorder.Body.String()
	if respBody == "hello" {
		t.Error("Auth block failed")
	}

	// Test cache expiration.
	// 1. Expect 1st request: succeed
	// 2. Change password in data store to empty, wait for cache to expire
	// 3. Expect 2nd request: fail
	// 4. Change password in data store back to valid password, wait for cache to expire
	// 5. Expect 3nd request: success
	r.Header.Set("Authorization", auth)
	recorder = httptest.NewRecorder()
	m.ServeHTTP(recorder, r)

	if recorder.Code == 401 {
		t.Error("Response is 401")
	}

	if recorder.Body.String() != "hello" {
		t.Error("Auth failed, got: ", recorder.Body.String())
	}

	dataStore.HashedPassword = nil
	time.Sleep(cacheExpireTime)

	recorder = httptest.NewRecorder()
	m.ServeHTTP(recorder, r)

	if recorder.Code != 401 {
		t.Error("Response not 401")
	}

	respBody = recorder.Body.String()
	if respBody == "hello" {
		t.Error("Auth block failed")
	}

	dataStore.HashedPassword = hashedPassword
	time.Sleep(cacheExpireTime)

	recorder = httptest.NewRecorder()
	m.ServeHTTP(recorder, r)

	if recorder.Code == 401 {
		t.Error("Response is 401")
	}

	if recorder.Body.String() != "hello" {
		t.Error("Auth failed, got: ", recorder.Body.String())
	}
}
