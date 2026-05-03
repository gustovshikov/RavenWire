FROM docker.io/library/golang:1.26.2-alpine3.23 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /pcap_ring_writer ./cmd/pcap-ring-writer

FROM docker.io/library/alpine:3.23.4

COPY --from=builder /pcap_ring_writer /usr/local/bin/pcap_ring_writer

ENTRYPOINT ["/usr/local/bin/pcap_ring_writer"]
