#! /bin/sh
# autogen-all.sh
# Copyright (C) 2024 g10 Code GmbH
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# This script is a helper to run the autogen.sh script for gpgme and the
# nested packages of the C++, Qt, and Python bindings.

prog=$(basename "$0")

packages=". lang/cpp"

fatal () {
    echo "${prog}:" "$*" >&2
    DIE=yes
}

info () {
    if [ -z "${SILENT}" ]; then
      echo "${prog}:" "$*" >&2
    fi
}

die_p () {
  if [ "$DIE" = "yes" ]; then
    echo "autogen.sh: Stop." >&2
    exit 1
  fi
}

DIE=no
SILENT=
tmp=$(dirname "$0")
tsdir=$(cd "${tmp}"; pwd)

am_lf='
'

if test x"$1" = x"--help"; then
  tmp="$(pwd)"
  cd "$tsdir" || fatal "error cd-ing to $tsdir"
  die_p
  ./autogen.sh --help | sed "s/autogen.sh/${prog}/" || fatal "error running ./autogen.sh --help"
  die_p
  exit 0
fi
if test x"$1" = x"--silent"; then
  SILENT=" --silent"
fi

for p in $packages; do
  info Running ./autogen.sh "$@" in $p ...
  curdir="$(pwd)"
  cd "$tsdir/$p" || fatal "error cd-ing to $tsdir/$p"
  die_p
  ./autogen.sh "$@" | sed "s/autogen.sh/${prog}/" || fatal "error running ./autogen.sh $@"
  die_p
  cd "$curdir" || fatal "error cd-ing back to $curdir"
  die_p
done
