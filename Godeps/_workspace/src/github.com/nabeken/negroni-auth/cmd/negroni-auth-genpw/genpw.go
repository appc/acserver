// Command negroni-auth-genpw generates hashed password using crypt/bcrypt package.
// A cost for bcrypt is picked from auth package.
// TODO(nabeken): Accept a cost by flag.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/appc/acserver/Godeps/_workspace/src/github.com/nabeken/negroni-auth"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [password]\n", os.Args[0])
	}

	if len(os.Args) != 2 {
		flag.Usage()
		os.Exit(2)
	}

	flag.Parse()

	password := flag.Arg(0)
	hashed, err := auth.Hash(password)
	if err != nil {
		fmt.Fprintln(os.Stderr, "unable to hash a password:", err)
		os.Exit(1)
	}

	fmt.Println(string(hashed))
}
