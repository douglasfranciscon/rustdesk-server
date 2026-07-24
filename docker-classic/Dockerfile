FROM alpine:3 AS certs

FROM scratch
# CA certificates so hbbs can reach CONTROL_API_URL over https
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY hbbs /usr/bin/hbbs
COPY hbbr /usr/bin/hbbr
WORKDIR /root
ENV HOME=/root
