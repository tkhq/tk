#!/bin/sh
set -eu

archive=$1
bundle=$2
identity=$3

verify() {
    cosign verify-blob-attestation "$1" \
        --bundle "$bundle" \
        --type slsaprovenance1 \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        --certificate-identity "$2"
}

verify "$archive" "$identity"

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
cp "$archive" "$temporary/tampered.tar.gz"
printf 'tampered' >> "$temporary/tampered.tar.gz"
if verify "$temporary/tampered.tar.gz" "$identity"; then
    echo 'error: Cosign accepted a modified archive' >&2
    exit 1
fi
for wrong_identity in "$identity.invalid" "${identity%@*}.invalid@${identity#*@}"; do
    if verify "$archive" "$wrong_identity"; then
        echo 'error: Cosign accepted a different workflow or tag' >&2
        exit 1
    fi
done
