#!/bin/sh
# Arguments are the configured DOCKER command, including any wrapper/options.
set -eu

install_help() {
    cat >&2 <<'EOF'
Install Docker Desktop or Docker Engine: https://docs.docker.com/engine/install/
Ensure its CLI is on PATH, or pass DOCKER=/path/to/docker to make.
EOF
}

if [ "$#" -eq 0 ]; then
    printf '%s\n' 'Docker command is empty. Set DOCKER=docker or a Docker executable path.' >&2
    exit 1
fi

if ! command -v "$1" >/dev/null 2>&1; then
    printf 'Docker command not found: %s\n' "$1" >&2
    install_help
    exit 1
fi

if docker_output=$(LC_ALL=C "$@" info --format '{{.ServerVersion}}' 2>&1); then
    exit 0
else
    docker_status=$?
fi

# Preserve Docker's diagnostic, including the selected endpoint or context.
printf 'Docker availability check failed:\n%s\n\n' "$docker_output" >&2
if [ "$docker_status" -eq 126 ] || [ "$docker_status" -eq 127 ]; then
    printf '%s\n' 'The configured Docker command could not be executed. Check DOCKER and any wrapper command.' >&2
    install_help
    exit 1
fi

case "$docker_output" in
    *[Pp]ermission\ denied*|*[Aa]ccess\ denied*|*[Oo]peration\ not\ permitted*)
        cat >&2 <<'EOF'
Docker access was denied for the current user.
For a local Linux Docker Engine, configure your user's Docker group access:
https://docs.docker.com/engine/install/linux-postinstall/
After adding group membership, log out and back in. If already configured, try:
  sg docker -c 'make -C ledger test'
For a remote or rootless daemon, check the selected context and its access permissions.
EOF
        ;;
    *[Cc]annot\ connect*|*connection\ refused*|*daemon\ is\ not\ running*|*Is\ the\ docker\ daemon\ running*|*no\ such\ file\ or\ directory*)
        cat >&2 <<'EOF'
The Docker daemon could not be reached.
Start Docker Desktop, or start a local systemd Docker Engine with:
  sudo systemctl start docker
If Docker is already running or is remote/rootless, check `docker context ls`
and DOCKER_HOST to ensure the CLI points to the intended daemon.
EOF
        ;;
    *)
        cat >&2 <<'EOF'
The Docker command ran, but the daemon availability check failed.
Use the diagnostic above to fix the configuration or connection. Check
`docker context ls`, DOCKER_HOST, and `docker info` (using your DOCKER override
if configured), then retry make.
EOF
        ;;
esac
exit 1
