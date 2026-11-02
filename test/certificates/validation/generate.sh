#!/bin/sh
# Regenerates the X.509 path-validation fixtures used by
# test/x509/x509_validator_test.dart. Requires OpenSSL >= 3.4
# (for -not_before/-not_after). Private keys are throw-away and are deleted.
set -eu
cd "$(dirname "$0")"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

NB=20250101000000Z
NA=20450101000000Z

key_rsa() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/$1.key" 2>/dev/null; }
key_ec() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$2 -out "$WORK/$1.key" 2>/dev/null; }

# self_signed NAME SUBJECT DIGEST
self_signed() {
  openssl req -new -x509 -key "$WORK/$1.key" -subj "$2" -$3 \
    -not_before $NB -not_after $NA \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out "$1.pem"
}

# issue NAME SUBJECT ISSUER DIGEST EXTFILE_CONTENT [NOT_BEFORE NOT_AFTER] [extra sigopts]
issue() {
  name=$1; subj=$2; issuer=$3; dgst=$4; ext=$5
  nb=${6:-$NB}; na=${7:-$NA}; shift 7 2>/dev/null || shift $#
  printf '%s\n' "$ext" > "$WORK/$name.ext"
  openssl req -new -key "$WORK/$name.key" -subj "$subj" -out "$WORK/$name.csr"
  openssl x509 -req -in "$WORK/$name.csr" -CA "$issuer.pem" -CAkey "$WORK/$issuer.key" \
    -set_serial 0x$(openssl rand -hex 8) -$dgst "$@" \
    -not_before $nb -not_after $na -extfile "$WORK/$name.ext" -out "$name.pem" 2>/dev/null
}

CA_EXT='basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid'
CA0_EXT='basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid'
LEAF_EXT='basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:server.test,DNS:*.wild.test,IP:127.0.0.1,IP:::1
authorityKeyIdentifier=keyid'

# ---- RSA chain: root (sha256) -> intermediate (sha384, pathlen 0) -> leaf (sha256)
key_rsa rsa_root;  self_signed rsa_root "/O=tlslite test/CN=Test RSA Root CA" sha256
key_rsa rsa_int;   issue rsa_int "/O=tlslite test/CN=Test RSA Intermediate CA" rsa_root sha384 "$CA0_EXT"
key_rsa rsa_leaf;  issue rsa_leaf "/O=tlslite test/CN=server.test" rsa_int sha256 "$LEAF_EXT"
# Same subject key re-signed with SHA-512 and with RSA-PSS (SHA-256, salt 32).
cp "$WORK/rsa_leaf.key" "$WORK/rsa_leaf_sha512.key"
issue rsa_leaf_sha512 "/O=tlslite test/CN=server.test" rsa_int sha512 "$LEAF_EXT"
cp "$WORK/rsa_leaf.key" "$WORK/rsa_leaf_pss.key"
issue rsa_leaf_pss "/O=tlslite test/CN=server.test" rsa_int sha256 "$LEAF_EXT" "$NB" "$NA" \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256

# Expired leaf, leaf for another host, leaf without serverAuth, CN-only leaf
key_rsa rsa_expired; issue rsa_expired "/CN=server.test" rsa_int sha256 "$LEAF_EXT" 20200101000000Z 20210101000000Z
key_rsa rsa_other;   issue rsa_other "/CN=other.test" rsa_int sha256 'basicConstraints=critical,CA:FALSE
extendedKeyUsage=serverAuth
subjectAltName=DNS:other.test'
key_rsa rsa_clientauth; issue rsa_clientauth "/CN=server.test" rsa_int sha256 'basicConstraints=critical,CA:FALSE
extendedKeyUsage=clientAuth
subjectAltName=DNS:server.test'
key_rsa rsa_cn_only; issue rsa_cn_only "/O=tlslite test/CN=cn-only.test" rsa_int sha256 'basicConstraints=critical,CA:FALSE'

# Leaf issued by a cert that is NOT a CA (CA:FALSE leaf used as issuer)
key_rsa rsa_by_leaf; issue rsa_by_leaf "/CN=server.test" rsa_leaf sha256 "$LEAF_EXT"
# pathlen violation: rsa_int has pathlen:0, so a sub-CA below it is invalid
key_rsa rsa_subca;   issue rsa_subca "/CN=Test RSA Sub CA" rsa_int sha256 "$CA_EXT"
key_rsa rsa_subleaf; issue rsa_subleaf "/CN=server.test" rsa_subca sha256 "$LEAF_EXT"
# CA whose keyUsage lacks keyCertSign
key_rsa rsa_noksign; issue rsa_noksign "/CN=Test RSA CA without keyCertSign" rsa_root sha256 'basicConstraints=critical,CA:TRUE
keyUsage=critical,digitalSignature'
key_rsa rsa_noksign_leaf; issue rsa_noksign_leaf "/CN=server.test" rsa_noksign sha256 "$LEAF_EXT"

# Untrusted root signing a leaf for the right host
key_rsa evil_root; self_signed evil_root "/O=tlslite test/CN=Untrusted Root CA" sha256
key_rsa evil_leaf; issue evil_leaf "/CN=server.test" evil_root sha256 "$LEAF_EXT"

# ---- ECDSA chain: root P-384 -> intermediate P-256 (ecdsa-with-SHA384) -> leaf P-256 (SHA256)
key_ec ec_root P-384; self_signed ec_root "/O=tlslite test/CN=Test ECDSA Root CA" sha384
key_ec ec_int P-256;  issue ec_int "/O=tlslite test/CN=Test ECDSA Intermediate CA" ec_root sha384 "$CA0_EXT"
key_ec ec_leaf P-256; issue ec_leaf "/O=tlslite test/CN=server.test" ec_int sha256 'basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:server.test,DNS:*.wild.test,IP:127.0.0.1,IP:::1'
cp "$WORK/ec_leaf.key" "$WORK/ec_leaf_sha512.key"
issue ec_leaf_sha512 "/O=tlslite test/CN=server.test" ec_int sha512 'basicConstraints=critical,CA:FALSE
extendedKeyUsage=serverAuth
subjectAltName=DNS:server.test'

echo "fixtures regenerated in $(pwd)"
