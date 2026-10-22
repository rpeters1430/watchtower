FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod main.go build-info.json ./
COPY static ./static
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /dashboard .
FROM alpine:3.24@sha256:71e9b7bae160ba167fa17414401b94cbcdaf3c32feeab9298bd794a2a0614c35
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 dashboard
COPY --from=build /dashboard /dashboard
COPY --from=build /src/build-info.json /build-info.json
USER dashboard
EXPOSE 8080
ENTRYPOINT ["/dashboard"]
