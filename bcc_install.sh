# SPDX-License-Identifier: GPL-3.0-or-later
# From eAudit (https://github.com/seclab-stonybrook/eaudit), (c) the eAudit
# authors, licensed under GPL-3.0-or-later (see LICENSES/GPL-3.0-or-later.txt).
# Not covered by Nitro's MIT license.

fatal() {
  echo "BCC installation failed at the following step: $1"
  exit 1
}

sudo apt update || fatal "apt update"
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm14 llvm-14-dev libclang-14-dev libpolly-14-dev python3 zlib1g-dev libelf-dev libfl-dev \
  python3-setuptools liblzma-dev libdebuginfod-dev \
  || fatal "apt install (of required development packages)"
mkdir -p src || fatal "mkdir"
cd src
[ -d bcc ] || git clone https://github.com/iovisor/bcc.git || fatal "cloning BCC source from iovisor"
mkdir -p bcc/build; cd bcc/build
cmake .. || fatal "cmake"
make || fatal "Building BCC from source"
sudo make install || fatal "installing BCC"
cmake -DPYTHON_CMD=/usr/bin/python3 .. || fatal "building python3 bindings"
pushd src/python/
( make && sudo make install ) || fatal "installing python bindings"