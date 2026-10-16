#!/bin/bash
# PatchGate colleague test kit — entrypoint of the kit's server/site containers (TEST KIT ONLY).
# The containers stand in for the two Ubuntu 24.04 VMs (PatchGate server, bank site VM). Real VMs run
# systemd; here we do the cgroup v2 nesting step docker:dind's entrypoint performs, then (re)start the
# inner Docker daemon if it is installed already (container restart / resume), then idle.
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  mkdir -p /sys/fs/cgroup/init
  xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || :
  sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || :
fi
if command -v dockerd >/dev/null 2>&1 && ! pgrep -x dockerd >/dev/null 2>&1; then
  rm -f /var/run/docker.pid /run/docker.pid
  setsid dockerd >>/var/log/dockerd.log 2>&1 < /dev/null &
fi
exec sleep infinity
