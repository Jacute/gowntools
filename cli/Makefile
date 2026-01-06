APP_NAME := gowncli
MODULE   := github.com/Jacute/gowntools
VERSION  := $(shell git describe --tags || echo "v.dev")

LDFLAGS := -s -w \
	-X 'github.com/Jacute/gowntools/cli/cmd.Version=$(VERSION)' \
	-X 'github.com/Jacute/gowntools/cli/cmd.Module=$(MODULE)'

.PHONY: build clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(APP_NAME)

clean:
	rm -rf bin/
