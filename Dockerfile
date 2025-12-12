FROM python:3.11-slim

ARG REPO_URL=https://github.com/earthonion/Netflix-N-Hack.git
ARG REPO_BRANCH=main

ENV DEBIAN_FRONTEND=noninteractive
ENV MITM_PORT=8080

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates build-essential libssl-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# Clone the repo specified at build time
RUN git clone --depth 1 --branch ${REPO_BRANCH} ${REPO_URL} repo || git clone --depth 1 ${REPO_URL} repo

WORKDIR /opt/repo

# Install mitmproxy
RUN pip install --no-cache-dir mitmproxy

# Entrypoint script will run mitmdump against PS4/proxy.py inside the cloned repo
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
