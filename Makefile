#
# Makefile wrapper around invoking a docker build using cmake
#

TOPDIR := $(realpath $(dir $(firstword $(MAKEFILE_LIST))))
BUILDDIR := $(abspath $(TOPDIR)/build)

DOCKER_IMAGE = standalone-build:latest
DOCKER_COMMAND ?= \
	docker run --rm --network=host -u docker \
		--user $(shell id -u):$(shell id -g) \
		-v $(TOPDIR):$(TOPDIR) \
		-w $(TOPDIR) \
			-i -t $(DOCKER_IMAGE)
DOCKER_SHELL = \
	docker run --rm --network=host -u docker \
		--user $(shell id -u):$(shell id -g) \
		-v $(TOPDIR):$(TOPDIR) \
		-w $(TOPDIR) \
			-i -t $(DOCKER_IMAGE) /bin/bash

CMAKE_COMMAND = cmake


all: build

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/.stamp_dockerimage: $(BUILDDIR)
$(BUILDDIR)/.stamp_dockerimage: tools/docker/standalone/Dockerfile
$(BUILDDIR)/.stamp_dockerimage:
ifeq ($(strip $(shell docker images -q $(DOCKER_IMAGE) 2> /dev/null)),)
	docker build --network=host -t $(DOCKER_IMAGE) \
		--build-arg PUID=$(shell id -u) \
		--build-arg PGID=$(shell id -g) \
		--file $(TOPDIR)/tools/docker/standalone/Dockerfile \
			$(TOPDIR)
endif
	touch $@

$(BUILDDIR)/.stamp_configure: $(BUILDDIR)/.stamp_dockerimage
	$(DOCKER_COMMAND) $(CMAKE_COMMAND) \
		-B $(BUILDDIR) -S $(TOPDIR)
	touch $@

.PHONY: configure
configure: $(BUILDDIR)/.stamp_configure

.PHONY: build
build: $(BUILDDIR)/.stamp_configure
	$(DOCKER_COMMAND) $(CMAKE_COMMAND) \
		--build $(BUILDDIR) $(if $(VERBOSE),--verbose)

build-%: $(BUILDDIR)/.stamp_configure
	$(DOCKER_COMMAND) $(CMAKE_COMMAND) \
		--build $(BUILDDIR)/default $(if $(VERBOSE),--verbose) -- $*

.PHONY: shell
shell: $(BUILDDIR)/.stamp_dockerimage
	$(DOCKER_SHELL) ||:

.PHONY: clean
clean:
	rm -rf $(BUILDDIR)

.PHONY: remove
remove:
	docker image rm $(DOCKER_IMAGE)
	rm -f $(BUILDDIR)/.stamp_dockerimage
