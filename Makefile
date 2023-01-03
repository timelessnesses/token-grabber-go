.PHONY: all build run

all: | build run

build:
	go build -o bin/main.exe main.go
run:
	./bin/main.exe