# syntax=docker/dockerfile:1
FROM docker.io/library/golang:1.25.4@sha256:f60eaa87c79e604967c84d18fd3b151b3ee3f033bcdade4f3494e38411e60963 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download
RUN go mod verify

COPY . .

RUN GOOS="${TARGETOS}" CGO_ENABLED=0 GOARCH="${TARGETARCH}" go build -ldflags="-w -s" -o main .

WORKDIR /app/build

RUN cp -r /app/main /app/LICENSE .

############################
# STEP 2 build service image
############################

FROM scratch

ENV SERVICE_VERSION="1.15.0"

# Import the user and group files from the builder.
COPY --from=builder /etc/passwd /etc/passwd
# Import the certs from the builder.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

WORKDIR /app

COPY --from=builder /app/build/* ./

# Use an unprivileged user.
USER 1000

CMD ["/app/main"]
