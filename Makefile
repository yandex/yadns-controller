#
# Makefile to build YADNS y2 controller
#

EXECUTABLE := y2
PROJECT := yadns-controller
DNSXDPBPF := yadns-xdp.bpf.o
BUILD := "GO"

CONFIG := y2.yaml

GO ?= go

LEGACY=legacy

# arcadia specific settings, in one project could be several
# binaries, each in its own "cmd" directory
PROJECT_HOME:=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))
PROJECT_PATH=$(PROJECT_HOME)/cmd/$(PROJECT)

DEBUG := "--debug"
#DEBUG := ""

GOFMT ?= gofmt -w
ECHO=   echo

BUILD_DATE := `date +%FT%T%z`

VERSION := `cat $(PROJECT_HOME)/VERSION.txt`
GITREVISION := `git rev-parse --short HEAD`

TAGS ?=

.PHONY: all
all: build

deploy: build

# alternative flags for bpf
#
# * bpf maps could be pinned or anonymous, by default
#   we have anonymous maps, to enable pinned variants
#   the following flag should be set in make
#   statements below
#
#   make PINNED_FLAGS=-D_PINNED_MAP

buildebpf:
	@${ECHO} "Building ebpf $(DNSXDPBPF)" ; \
	make -C $(PROJECT_HOME)/bpf clean ; \
	make -C $(PROJECT_HOME)/bpf PINNED_FLAGS=-D_PINNED_MAP ; \
	cp $(PROJECT_HOME)/bpf/$(DNSXDPBPF) $(PROJECT_HOME)/$(DNSXDPBPF) ; \
	ls -l $(PROJECT_HOME)/$(DNSXDPBPF)

.PHONY: build
build: $(PROJECT)

.PHONY: $(PROJECT)
$(PROJECT): $(GOFILES) buildebpf
	@${ECHO} "Build date: '$(BUILD_DATE)'"
	@${ECHO} "Project home: '$(PROJECT_HOME)'"
	@${ECHO} "Project path: '$(PROJECT_PATH)'"
	@${ECHO} "Revision: '$(GITREVISION)'"
	cd $(PROJECT_HOME) ; \
	$(GOFMT) . ; \
	if [ "${BUILD}" = "GO" ]; then \
		${ECHO} "Building native go..."; \
		cd $(PROJECT_PATH) && $(GO) build -v -tags '$(TAGS)' \
			-ldflags="-X 'main.Version=$(VERSION)' \
			-X 'main.Date=$(BUILD_DATE)' \
			-X 'main.Revision=$(GITREVISION)'" \
			-o $(PROJECT_HOME)/$(EXECUTABLE); \
	fi; \
	$(PROJECT_HOME)/$(EXECUTABLE) version ; \
	ls -l $(PROJECT_HOME)/$(EXECUTABLE)

test:
	@${ECHO} "Running testing for '$(PROJECT)' ... "
	$(GO) test  ./...

.PHONY: clean
clean:
	@${ECHO} "Cleaning build"
	cd $(PROJECT_PATH) && $(GO) clean
	test -f $(PROJECT_HOME)/$(EXECUTABLE) && rm $(PROJECT_HOME)/$(EXECUTABLE) || true
	test -f $(PROJECT_HOME)/$(DNSXDPBPF) && rm $(PROJECT_HOME)/$(DNSXDPBPF) || true

.PHONY: run
run:
	@${ECHO} "Running y2 on minimal example configuration"
	cp $(PROJECT_HOME)/examples/example.com /var/tmp/example.com
	sudo $(PROJECT_HOME)$(EXECUTABLE) -C $(PROJECT_HOME)$(CONFIG) server -B $(PROJECT_HOME)$(DNSXDPBPF) start --debug
