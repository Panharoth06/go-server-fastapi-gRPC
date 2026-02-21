FROM golang:1.25-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/go-server ./cmd

FROM gcr.io/distroless/base-debian12
COPY --from=builder /bin/go-server /go-server
EXPOSE 50051
ENTRYPOINT ["/go-server"]
