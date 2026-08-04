FROM golang:1.26.2-alpine3.23@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS build
WORKDIR /src

COPY go.* ./
RUN go mod download && go mod verify

COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -mod=readonly -o /executor .

FROM ubuntu:26.04@sha256:7b202b0e2e0028c6250f5fcf41d04df492d145a1654c6995a6553f0c1f6f1960
# Date-stamped Ubuntu archive snapshot. Pinning makes the apt layer
# reproducible byte-for-byte across rebuilds (same date → same packages → same image hash). 
ENV DEBIAN_FRONTEND=noninteractive \
    HOME=/tmp

COPY --from=build /executor /executor
RUN mkdir -p /workspace /run/execsock \
    && chown 1000:1000 /workspace /run/execsock
# bashuser (uid 1001) is the identity /exec drops bash into. It exists so
# /user-uploads can be owned by uid 1000 (executor) with mode 755 — bashuser
# falls into "other" perms (rx) and cannot mutate uploaded files.
RUN groupadd -g 1001 bashuser \
    && useradd -u 1001 -g 1001 -M -s /bin/bash bashuser
# File capabilities on the executor binary so SETUID/SETGID survive the
# uid drop from root → 1000. Without this, --cap-add SETUID is in the
# bounding set but not the effective set for a non-root process, and
# /exec's setuid(1001) call returns EPERM.
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
    && setcap cap_setuid,cap_setgid+ep /executor \
    && apt-get purge -y libcap2-bin && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*
VOLUME /run/execsock
WORKDIR /workspace
CMD ["/executor"]
