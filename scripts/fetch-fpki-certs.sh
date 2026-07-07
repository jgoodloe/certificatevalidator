#!/usr/bin/env sh
# Download the Federal PKI certs and lay them out where this project expects:
#
#   certs/fpki-cas.pem        <- root + issued CAs, one PEM (nginx CA filter)
#   trust/anchors/            <- root cert (validation trust anchor)
#   trust/intermediates/      <- CAs issued by the root
#
# Sources are the GSA FPKI repository, documented at
# https://www.idmanagement.gov/implement/trust-fcpca/
#
# Pass --bridge to also include the Federal Bridge CA G4 chain (PIV-I /
# cross-certified partner credentials).
#
# For NIST *test* PIV cards, this script does not apply — fetch the test PKI
# root and intermediates from
# https://csrc.nist.gov/projects/piv/nist-piv-test-cards instead and drop
# them in trust/anchors/ and trust/intermediates/.

set -eu

cd "$(dirname "$0")/.."
mkdir -p certs trust/anchors trust/intermediates
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch_chain() {
    # $1 = name, $2 = root cert URL, $3 = issued-CAs p7c URL
    name=$1
    curl -fsSL "$2" -o "$work/$name.crt"
    curl -fsSL "$3" -o "$work/$name-issued.p7c"
    openssl x509 -inform DER -in "$work/$name.crt" -out "$work/$name.pem" \
        2>/dev/null || cp "$work/$name.crt" "$work/$name.pem"
    openssl pkcs7 -inform DER -in "$work/$name-issued.p7c" \
        -print_certs -out "$work/$name-issued.pem"
    cp "$work/$name.pem" "trust/anchors/$name.pem"
    cp "$work/$name-issued.pem" "trust/intermediates/$name-issued.pem"
    cat "$work/$name.pem" "$work/$name-issued.pem"
}

{
    fetch_chain fcpcag2 \
        http://repo.fpki.gov/fcpca/fcpcag2.crt \
        http://repo.fpki.gov/fcpca/caCertsIssuedByfcpcag2.p7c

    if [ "${1:-}" = "--bridge" ]; then
        fetch_chain fbcag4 \
            http://repo.fpki.gov/bridge/fbcag4.crt \
            http://repo.fpki.gov/bridge/caCertsIssuedByfbcag4.p7c
    fi
} > certs/fpki-cas.pem

echo "Wrote certs/fpki-cas.pem ($(grep -c 'BEGIN CERTIFICATE' certs/fpki-cas.pem) certs)"
echo "Anchors:       $(ls trust/anchors)"
echo "Intermediates: $(ls trust/intermediates)"
