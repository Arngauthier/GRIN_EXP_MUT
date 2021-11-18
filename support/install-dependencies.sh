#!/bin/bash

set -e

export DEBIAN_FRONTEND=noninteractive

apt-get update

apt-get install --no-install-recommends --yes \
  aufs-tools \
  build-essential \
  ca-certificates \
  cmake \
  curl \
  gawk \
  git \
  libglib2.0-dev \
  m4 \
  pkg-config \
  python \
  python-pyelftools \
  python3 \
  python3-cffi \
  python3-pygraphviz \
  python3-setuptools \
  sed \
  texinfo \
  valgrind \
  zlib1g-dev \
  libmpc-dev

if ! which git-lfs >& /dev/null; then
  curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | bash
  apt-get install --no-install-recommends --yes git-lfs
fi
