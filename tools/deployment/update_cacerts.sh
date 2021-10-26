#!/bin/bash
# Grabs the latest Mozilla CA certificate store
# https://curl.se/docs/caextract.html

set -euo pipefail

# Restore timestamp of certs.pem on a fresh git clone
#UNIX_TIME=$(git log -1 --format="%at" -- certs.pem)
#TOUCH_TIME=$(sudo date -t $UNIX_TIME +'%Y%m%d%H%M.%S')
#touch -t ${TOUCH_TIME} certs.pem

# On macOS
touch -t $(git log -1 --pretty=format:%cd --date=format:%Y%m%d%H%m.%S -- certs.pem) certs.pem

# --time-cond will use timestamp of local certs.pem
HTTP_CODE=$(curl --remote-name --time-cond certs.pem https://curl.se/ca/cacert.pem -w "%{http_code}")
if [ $HTTP_CODE -eq 200 ]; then
    echo "Downloaded new cacert.pem and comparing SHA256 checksum"
    curl -s https://curl.se/ca/cacert.pem.sha256 -o cacert.pem.sha256sum
    shasum -c cacert.pem.sha256sum
elif [ $HTTP_CODE -eq 304 ]; then
    echo "Mozilla CA certificates have not been updated."
else
    echo "Curl response code: $HTTP_CODE :("
fi
