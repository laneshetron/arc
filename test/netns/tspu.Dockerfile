# arc through mini-tspu (test/netns/tspu.sh), for machines without Linux
# network namespaces. mini-tspu is a separate repository, passed as a
# named build context:
#
#   docker build -f test/netns/tspu.Dockerfile --build-context mini-tspu=../mini-tspu -t arc-tspu .
#   docker run --rm --privileged arc-tspu [SCENARIO...]
FROM golang:1.26.11-bookworm AS tspu
WORKDIR /src
COPY --from=mini-tspu go.mod go.sum ./
RUN go mod download
COPY --from=mini-tspu . .
RUN CGO_ENABLED=0 go build -o /out/ ./cmd/mini-tspu

FROM golang:1.26.11-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/ ./cmd/arc-client ./cmd/arc-relay

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iptables iperf3 iputils-ping procps ethtool python3 tcpdump && rm -rf /var/lib/apt/lists/*
COPY --from=tspu /out/ /arc/bin/
COPY --from=build /out/ /arc/bin/
COPY test/netns/tspu.sh /arc/
ENTRYPOINT ["/arc/tspu.sh", "/arc/bin"]
