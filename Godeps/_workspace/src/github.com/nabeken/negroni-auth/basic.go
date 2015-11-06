// Package auth implements Basic authentication.
package auth

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/appc/acserver/Godeps/_workspace/src/github.com/codegangsta/negroni"
	"github.com/appc/acserver/Godeps/_workspace/src/github.com/pmylund/go-cache"
	"github.com/appc/acserver/Godeps/_workspace/src/golang.org/x/crypto/bcrypt"

	"github.com/appc/acserver/Godeps/_workspace/src/github.com/nabeken/negroni-auth/datastore"
)

const (
	defaultCacheExpireTime = 10 * time.Minute
	defaultCachePurseTime  = 60 * time.Second
)

// See https://godoc.org/golang.org/x/crypto/bcrypt#pkg-constants for more details.
var BcryptCost = 10

// NewSimpleBasic returns *datastore.Simple built from userid, password.
func NewSimpleBasic(userId, password string) (*datastore.Simple, error) {
	hashedPassword, err := Hash(password)
	if err != nil {
		return nil, err
	}

	return &datastore.Simple{
		Key:   userId,
		Value: hashedPassword,
	}, nil
}

// requireAuth writes error to client which initiates the authentication process
// or requires reauthentication.
func requireAuth(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Basic realm=\"Authorization Required\"")
	http.Error(w, "Not Authorized", http.StatusUnauthorized)
}

// getCred get userid, password from request.
func getCred(req *http.Request) (string, string) {
	// Split authorization header.
	s := strings.SplitN(req.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 || s[0] != "Basic" {
		return "", ""
	}

	// Decode credential.
	cred, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return "", ""
	}

	// Split credential into userid, password.
	pair := strings.SplitN(string(cred), ":", 2)
	if len(pair) != 2 {
		return "", ""
	}

	return pair[0], pair[1]
}

// Hash returns a hashed password.
func Hash(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
}

// NewBasic returns a negroni.HandlerFunc that authenticates via Basic auth using data store.
// Writes a http.StatusUnauthorized if authentication fails.
func NewBasic(datastore datastore.Datastore) negroni.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
		// Extract userid, password from request.
		userId, password := getCred(req)

		if userId == "" {
			requireAuth(w)
			return
		}

		// Extract hashed passwor from credentials.
		hashedPassword, found := datastore.Get(userId)
		if !found {
			requireAuth(w)
			return
		}

		// Check if the password is correct.
		err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		// Password not correct. Fail.
		if err != nil {
			requireAuth(w)
			return
		}

		r := w.(negroni.ResponseWriter)

		// Password correct.
		if r.Status() != http.StatusUnauthorized {
			next(w, req)
		}
	}
}

// Basic returns a negroni.HandlerFunc that authenticates via Basic Auth.
// Writes a http.StatusUnauthorized if authentication fails.
func Basic(userid, password string) negroni.HandlerFunc {
	datastore, err := NewSimpleBasic(userid, password)
	if err != nil {
		panic(err)
	}

	return NewBasic(datastore)
}

// CacheBasic returns a negroni.HandlerFunc that authenticates via Basic auth using cache.
// Writes a http.StatusUnauthorized if authentication fails.
func CacheBasic(datastore datastore.Datastore, cacheExpireTime, cachePurseTime time.Duration) negroni.HandlerFunc {
	var basic = NewBasic(datastore)
	var c = cache.New(cacheExpireTime, cachePurseTime)

	return func(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
		// Get credential from request header.
		credential := req.Header.Get("Authorization")
		// Get authentication status by credential.
		authenticated, found := c.Get(credential)

		// Cache hit
		if found && (authenticated == "true") {
			next(w, req)
		} else { // Cache miss. Unauthenticated.
			basic(w, req, next)
			r := w.(negroni.ResponseWriter)

			// Password correct.
			if r.Status() != http.StatusUnauthorized {
				c.Set(credential, "true", cache.DefaultExpiration)
			}
		}
	}
}

// CacheBasicDefault returns a negroni.HandlerFunc that authenticates via Basic auth using cache.
// with default cache configuration. Writes a http.StatusUnauthorized if authentication fails.
func CacheBasicDefault(datastore datastore.Datastore) negroni.HandlerFunc {
	return CacheBasic(datastore, defaultCacheExpireTime, defaultCachePurseTime)
}
