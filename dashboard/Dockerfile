FROM golang:1.27-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY go.mod main.go ./
COPY static ./static
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /dashboard .
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 dashboard
COPY --from=build /dashboard /dashboard
USER dashboard
EXPOSE 8080
ENTRYPOINT ["/dashboard"]
