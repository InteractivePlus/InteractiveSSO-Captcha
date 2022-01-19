# syntax=docker/dockerfile:1

FROM golang:1.17-alpine
WORKDIR /app
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# copy necessary files
COPY *.go ./

RUN go build -o /captchaservice

FROM alpine
WORKDIR /app
COPY --from=0 /captchaservice ./
COPY config_docker_with_environment.json ./

EXPOSE $PORT
CMD ["/app/captchaservice", "-conf", "/app/config_docker_with_environment.json"]