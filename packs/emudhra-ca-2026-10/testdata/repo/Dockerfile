FROM golang:1.26.4-alpine AS build
RUN apk add --no-cache ca-certificates git
FROM node:22 AS web
FROM node:18-alpine AS old
FROM alpine:3.20
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
FROM python:3.12-slim
RUN pip install -U certifi pip
FROM oven/bun:1.2
FROM scratch
