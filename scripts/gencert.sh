#!/bin/sh
# Generate local test credentials, renewing before they can expire mid-suite.
set -eu

cert=$1
key=$2
days=$3
shift 3

if [ -s "$key" ] &&
   openssl x509 -in "$cert" -noout -checkend 86400 >/dev/null 2>&1; then
  exit 0
fi

mkdir -p "$(dirname "$cert")" "$(dirname "$key")"
openssl req -x509 -nodes -days "$days" -newkey rsa:2048 \
  -keyout "$key" -out "$cert" "$@"
