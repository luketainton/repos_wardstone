FROM golang:1.27.3-bookworm AS build
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY src/ ./src/
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /wardstone ./src

FROM debian:bookworm-slim
RUN groupadd --gid 10001 wardstone && useradd --uid 10001 --gid wardstone --no-create-home wardstone \
    && mkdir -m 700 /data /bootstrap && chown wardstone:wardstone /data /bootstrap
COPY --from=build /wardstone /usr/local/bin/wardstone
USER 10001:10001
EXPOSE 8443
VOLUME ["/data", "/bootstrap"]
ENTRYPOINT ["/usr/local/bin/wardstone"]
