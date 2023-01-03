.PHONY: all build run

all: | build run

build:
	set GOOS=windows
	set GOARCH=amd64
	go build -o bin/main.exe main.go
run:
	./bin/main.exe