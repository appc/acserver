#!/bin/sh
set -e
dir=$( dirname "$0" )

[ -f ${GOPATH}/bin/go-bindata ] || go get github.com/jteeuwen/go-bindata

go-bindata -nomemcopy -pkg main -o ${dir}/bindata.go ${dir}/templates/...
godep go build
