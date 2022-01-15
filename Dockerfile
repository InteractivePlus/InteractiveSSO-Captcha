# syntax=docker/dockerfile:1

FROM golang:1.17-alpine
WORKDIR /app
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# copy necessary files
COPY *.go ./
COPY config_docker_with_environment.json ./

RUN go build -o /captchaservice
EXPOSE 80
CMD ["/captchaservice", "-conf", "config_docker_with_environment.json"]