SHELL := /bin/sh

.PHONY: test matrix rustpbx-matrix asterisk-matrix all-matrix udp-direct udp-proxy tcp-direct tcp-proxy tls-direct tls-proxy clean

PBX ?= rustpbx

test:
	@./run.sh $(PBX) $(TRANSPORT) $(MEDIA)

matrix:
	@./run.sh --matrix $(PBX)

rustpbx-matrix:
	@./run.sh --matrix rustpbx

asterisk-matrix:
	@./run.sh --matrix asterisk

all-matrix:
	@./run.sh --matrix all

udp-direct tcp-direct tls-direct udp-proxy tcp-proxy tls-proxy:
	@./run.sh $(PBX) $(word 1,$(subst -, ,$@)) $(word 2,$(subst -, ,$@))

clean:
	@rm -rf artifacts
