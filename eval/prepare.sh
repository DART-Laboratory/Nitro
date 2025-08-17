#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "[1/3] Granting execute permissions to scripts containing 'run' in the current directory..."
find "$SCRIPT_DIR" -maxdepth 1 -type f -name "*run*" -exec chmod +x {} \;

echo "[2/3] Installing and configuring nginx and httperf..."
if ! command -v apt >/dev/null 2>&1; then
  echo "apt package manager not found. Cannot install nginx/httperf automatically." >&2
  exit 1
fi

sudo apt update
sudo apt install -y nginx httperf

echo "Enabling and starting nginx..."
sudo systemctl enable --now nginx

WEBROOT="/var/www/html"
echo "Copying static contents to $WEBROOT ..."
if [ -d "$SCRIPT_DIR/httperf/contents" ]; then
  sudo rm -rf "${WEBROOT:?}/"*
  sudo cp -r "$SCRIPT_DIR/httperf/contents/"* "$WEBROOT"/
else
  echo "Warning: $SCRIPT_DIR/httperf/contents not found, skipping copy." >&2
fi
sudo systemctl restart nginx

echo "[3/3] Downloading and preparing kernel source directory..."
URL="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/snapshot/linux-6.5-rc7.tar.gz"
TAR="linux-6.5-rc7.tar.gz"
EXTRACT_DIR="linux-6.5-rc7"
TARGET_DIR="kernel"

echo "Downloading $URL ..."
wget -q --show-progress -O "$TAR" "$URL"

echo "Extracting $TAR ..."
tar -xvzf "$TAR"

echo "Moving to $TARGET_DIR/ ..."
rm -rf "$TARGET_DIR"
mv -f "$EXTRACT_DIR" "$TARGET_DIR"

echo "Cleaning up temporary files..."
rm -f "$TAR"

echo "All steps completed successfully."
