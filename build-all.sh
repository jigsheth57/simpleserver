#!/bin/sh

GOOS=linux GOARCH=amd64 go build
LINUX64_SHA1=`cat simpleserver | openssl sha1 | cut -d " " -f2-`
mkdir -p bin/linux64
mv simpleserver bin/linux64

GOOS=darwin GOARCH=amd64 go build
OSX_SHA1=`cat simpleserver | openssl sha1 | cut -d " " -f2-`
mkdir -p bin/osx
mv simpleserver bin/osx

GOOS=windows GOARCH=amd64 go build
WIN64_SHA1=`cat simpleserver.exe | openssl sha1 | cut -d " " -f2-`
mkdir -p bin/win64
mv simpleserver.exe bin/win64

GOOS=windows GOARCH=386 go build
WIN32_SHA1=`cat simpleserver.exe | openssl sha1 | cut -d " " -f2-`
mkdir -p bin/win32
mv simpleserver.exe bin/win32

UPDATED_TIME=`date +"%Y-%m-%dT%T%Z"`
cat repo-index.yml.template |
sed "s/osx-sha1/$OSX_SHA1/" |
sed "s/win64-sha1/$WIN64_SHA1/" |
sed "s/win32-sha1/$WIN32_SHA1/" |
sed "s/linux64-sha1/$LINUX64_SHA1/" |
sed "s/_TIME_/$UPDATED_TIME/" |
cat > repo-index.yml 2>&1
cat repo-index.yml

rm main