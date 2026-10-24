FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm AS build
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY src/ ./src/
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-$(go env GOARCH)}" \
    go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /wardstone ./src

FROM debian:bookworm-slim
RUN groupadd --gid 10001 wardstone && useradd --uid 10001 --gid wardstone --no-create-home wardstone \
    && mkdir -m 700 /data /bootstrap && chown wardstone:wardstone /data /bootstrap
COPY --from=build /wardstone /usr/local/bin/wardstone
USER 10001:10001
EXPOSE 8443
VOLUME ["/data", "/bootstrap"]
ENTRYPOINT ["/usr/local/bin/wardstone"]
