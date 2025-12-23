## syntax=docker/dockerfile:1
FROM gcr.io/distroless/static-debian12:nonroot
COPY s3-rbac-proxy /usr/local/bin/s3-rbac-proxy
ENTRYPOINT ["/usr/local/bin/s3-rbac-proxy"]
CMD ["-config", "/etc/s3-rbac-proxy/config.yaml"]
