# Runtime image for check.sh: Debian with systemd as PID 1 and the Linux
# gyges/gygesd binaries that run.sh built.
FROM debian:trixie
RUN apt-get update -qq \
 && apt-get install -y -qq systemd systemd-sysv procps passwd >/dev/null \
 && rm -rf /var/lib/apt/lists/*
COPY gyges gygesd /usr/local/bin/
COPY check.sh /usr/local/bin/check-hardened
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
