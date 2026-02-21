FROM golang:1.25 AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/go-server ./cmd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/go-server /go-server
EXPOSE 50051
USER nonroot:nonroot
ENTRYPOINT ["/go-server"]
