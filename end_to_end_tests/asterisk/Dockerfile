FROM alpine:3.22

# Alpine 3.22 pins the Asterisk 20 LTS package used as the independent PBX
# implementation.  Keep the exact package revision so a distribution update
# cannot silently change the comparison baseline.
RUN apk add --no-cache asterisk=20.11.1-r6 \
    && rm -f /etc/asterisk/*

COPY asterisk/config/ /etc/asterisk/

ENTRYPOINT ["/usr/sbin/asterisk", "-f", "-U", "root", "-G", "root", "-vvv"]
