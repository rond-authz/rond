############################
# STEP 1 build executable binary
############################
FROM golang:1.21.6 AS builder

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download
RUN go mod verify

COPY . .

RUN GOOS=linux CGO_ENABLED=0 GOARCH=amd64 go build -ldflags="-w -s" -o main .

WORKDIR /app/build

RUN cp -r /app/main /app/LICENSE .

############################
# STEP 2 build service image
############################

FROM scratch

ARG COMMIT_SHA=<not-specified>

LABEL maintainer="rond@rond-authz.io" \
  name="rond" \
  vcs.sha="$COMMIT_SHA"

LABEL org.opencontainers.image.description "Rönd is a lightweight container that distributes security policy enforcement throughout your application."

ENV SERVICE_VERSION="1.12.3"

# Import the user and group files from the builder.
COPY --from=builder /etc/passwd /etc/passwd
# Import the certs from the builder.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

WORKDIR /app

COPY --from=builder /app/build/* ./

# Use an unprivileged user.
USER 1000

CMD ["/app/main"]
