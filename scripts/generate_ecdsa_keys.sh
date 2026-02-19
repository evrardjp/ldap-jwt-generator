#!/bin/sh

set -o errexit
set -o pipefail

# Create a temporary directory using mktemp
TEMP_DIR="$(mktemp -d -t ldap-jwt-signer)"
KEY_FILE="ecdsa.key"
PUB_KEY_FILE="ecdsa.pub"

openssl ecparam -genkey -name secp521r1 -noout -out "${TEMP_DIR}/${KEY_FILE}"
openssl ec -in "${TEMP_DIR}/${KEY_FILE}" -pubout -out "${TEMP_DIR}/${PUB_KEY_FILE}"

echo "Files ecdsa.{key,pub} have been stored in ${TEMP_DIR}"
