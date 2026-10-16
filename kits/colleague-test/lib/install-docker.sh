#!/bin/bash
# PatchGate colleague test kit — Docker Engine for the kit's server container (TEST KIT ONLY).
# Same source and key pin as installers/server/install-patchgate.sh (official apt repo, download.docker.com).
# Done before the server installer runs because the PatchGate images are `docker load`ed from the kit first
# (registry mode with an empty registry = "images already loaded locally").
set -euo pipefail
DOCKER_APT_KEY_FPR="9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
export DEBIAN_FRONTEND=noninteractive
if ! command -v dockerd >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg iproute2 iptables openssl procps >/dev/null 2>/var/log/kit-apt.err || { cat /var/log/kit-apt.err; exit 1; }
  install -m 0755 -d /etc/apt/keyrings
  key="$(mktemp)"
  curl -fsSL --proto "=https" --tlsv1.2 https://download.docker.com/linux/ubuntu/gpg -o "$key"
  fpr="$(gpg --show-keys --with-colons "$key" 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')"
  [ "$fpr" = "$DOCKER_APT_KEY_FPR" ] || { echo "Docker apt key fingerprint mismatch ($fpr)"; exit 1; }
  gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg < "$key"; rm -f "$key"; chmod a+r /etc/apt/keyrings/docker.gpg
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>/var/log/kit-apt.err || { cat /var/log/kit-apt.err; exit 1; }
fi
if ! docker info >/dev/null 2>&1; then
  pgrep -x dockerd >/dev/null 2>&1 || { rm -f /var/run/docker.pid; setsid dockerd >>/var/log/dockerd.log 2>&1 < /dev/null & }
  for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 2; done
fi
docker info >/dev/null 2>&1 || { tail -20 /var/log/dockerd.log; echo "inner dockerd did not start"; exit 1; }
echo "Docker $(docker version --format '{{.Server.Version}}') (storage $(docker info --format '{{.Driver}}'), cgroup v$(docker info --format '{{.CgroupVersion}}'))"
