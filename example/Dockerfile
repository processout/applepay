# Build image

FROM golang:latest AS build

RUN apt-get update && \
	apt-get install -y libssl-dev

COPY . /go/src/github.com/processout/applepay/example
WORKDIR /go/src/github.com/processout/applepay/example
RUN go build -ldflags '-w' -o /applepay .

# Final image

FROM alpine:latest

RUN apk add --update \
	ca-certificates \
	openssl
RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2

COPY --from=build /applepay /applepay
RUN chmod +x /applepay
COPY AppleRootCA-G3.crt /AppleRootCA-G3.crt
COPY static /static
COPY certs /certs

ENTRYPOINT /applepay
