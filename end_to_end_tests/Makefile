SHELL := /bin/sh

.PHONY: test matrix udp-direct udp-proxy tcp-direct tcp-proxy tls-direct tls-proxy clean

test:
	@./run.sh $(TRANSPORT) $(MEDIA)

matrix:
	@./run.sh --matrix

udp-direct tcp-direct tls-direct udp-proxy tcp-proxy tls-proxy:
	@./run.sh $(word 1,$(subst -, ,$@)) $(word 2,$(subst -, ,$@))

clean:
	@rm -rf artifacts
