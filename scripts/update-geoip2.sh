#!/bin/sh

GEOLITE2_ASN="http://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz"

DB=$(curl -s "${GEOLITE2_ASN}" | gzip -d | tar xvf - \
     --wildcards --no-anchored GeoLite2-ASN.mmdb)

echo "${DB}"

# Optional move downloaded database to specific location
if [ $1 ]; then
    mv "${DB}" "${1}"
fi
