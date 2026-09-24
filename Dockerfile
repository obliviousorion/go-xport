FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/xport ./cmd/xport

FROM alpine:3.20
RUN apk --no-cache add ca-certificates curl bash
COPY --from=builder /bin/xport /usr/local/bin/xport
CMD ["xport"]
