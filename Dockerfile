FROM golang:1.16.5-alpine3.13 as gobuilder

# 替换为国内源
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories

ENV GO111MODULE="on"
ENV GOPROXY="https://goproxy.cn,direct"
ENV CGO_ENABLED=0

WORKDIR /go/src/app
COPY . .

RUN apk update && apk upgrade && apk add --no-cache ca-certificates
RUN update-ca-certificates
RUN go build

FROM scratch

WORKDIR /root

COPY --from=gobuilder /go/src/app/wecomchan .
COPY --from=gobuilder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8080

CMD ["./wecomchan"]
