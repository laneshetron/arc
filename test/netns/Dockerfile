# Runs test/netns/e2e.sh in a privileged container, for development on
# machines without Linux network namespaces (e.g. macOS):
#
#   docker build -f test/netns/Dockerfile -t arc-e2e .
#   docker run --rm --privileged arc-e2e
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/ ./cmd/arc-client ./cmd/arc-relay

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iptables iperf3 iputils-ping procps && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ /arc/bin/
COPY test/netns/e2e.sh /arc/e2e.sh
ENTRYPOINT ["/arc/e2e.sh", "/arc/bin"]
