FROM alpine:3.19 AS builder
RUN apk add --no-cache rust cargo musl-dev
WORKDIR /build
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl -p chronyd-rs -p chronyc-rs

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/chronyd-rs /usr/sbin/chronyd-rs
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/chronyc-rs /usr/bin/chronyc-rs
COPY dist/systemd/chronyd-rs.service /etc/systemd/system/chronyd-rs.service
EXPOSE 123/udp 323/udp 4460/tcp
ENTRYPOINT ["/usr/sbin/chronyd-rs"]
CMD ["-f", "/etc/chrony/chrony.conf"]
