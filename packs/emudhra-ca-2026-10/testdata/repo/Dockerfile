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
# Pinned by digest (node:22.1.0-bookworm-slim as of 2026-01-10); bump deliberately.
FROM node:22.1.0-bookworm-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS pinned
FROM nginx:1.27-alpine AS serve
COPY --from=web /app/dist /usr/share/nginx/html
