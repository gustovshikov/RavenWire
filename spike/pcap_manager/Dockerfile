FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -o /pcap_manager .

FROM alpine:3.19
COPY --from=builder /pcap_manager /usr/local/bin/pcap_manager
ENTRYPOINT ["/usr/local/bin/pcap_manager"]
