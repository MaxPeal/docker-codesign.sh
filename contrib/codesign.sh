#!/bin/sh

# To the extent possible under law, Viktor Szakats (vsz.me)
# has waived all copyright and related or neighboring rights to this
# script.
# CC0 - https://creativecommons.org/publicdomain/zero/1.0/

# This script will create a self-signed root certificate, along with a code
# signing certificate in various formats, trying to use the best available
# crypto/practice all along. Then, it will create a test executable and code
# sign it using both osslsigncode and signtool.exe (on Windows only) and
# verify those signature using osslsigncode and sigcheck.exe (on Windows only).

# Requires:
#   openssl 1.1.x, gpg, osslsigncode 2.1.0, GNU tail, base58
# Mac:
#   brew install openssl gnupg osslsigncode coreutils
# Win:
#   pacman --sync openssl gnupg mingw-w64-{i686,x86_64}-osslsigncode
#   sigcheck64.exe:
#     curl --user-agent '' --remote-name --remote-time --xattr https://live.sysinternals.com/tools/sigcheck64.exe
#   signtool.exe:
#     part of Windows SDK

# - .pem is a format, "Privacy Enhanced Mail", text, base64-encoded binary
#           (with various twists, if encrypted)
# - .der is a format, Distinguished Encoding Rules for ASN.1, binary
# - .crt/.cer denote a certificate or multiple certificates
# - .csr is certificate signing request, DER format.
# - .srl is serial number (for certificate generation)
# - .pfx is Microsoft name for .p12
#           = PKCS #12 = encrypted certificate(s) + private keys, DER format.
#           Strictly PKCS #12-compliant systems (like MS/Apple tools) only
#           understand weakly encrypted, standard .p12 files. OpenSSL-based
#           tools (like osslsigncode) will accept modern crypto algos as well.
#           Fun read: https://www.cs.auckland.ac.nz/~pgut001/pubs/pfx.html
# - .pvk is Microsoft proprietary Private Key format, encrypted (weak crypto)
# - .spc is Microsoft name for .p7b (PKCS #7) = Software Publisher Certificate
#           (or Certificate Bundle), internally it's DER format and contains
#           certificates.
#
# - private-key ASN.1 data structure in PEM or DER format
# - public-key  ASN.1 data structure in PEM or DER format, but it may also
#               exist in one-liner OpenSSH key format RFC 4251.

case "$(uname)" in
  *Darwin*)
    alias openssl=/usr/local/opt/openssl@1.1/bin/openssl
    readonly os='mac';;
  *_NT*)
    # To find osslsigncode
    PATH="/mingw64/bin:${PATH}"
    readonly os='win';;
  Linux*)
    readonly os='linux';;
esac

# Redirect stdout securely to non-world-readable files
privout() {
  o="$1"; rm -f "$o"; install -m 600 /dev/null "$o"; shift
  (
    "$@"
  ) >> "$o"
}

readonly base="$1"
readonly revi="$2"

readonly compname="${base}"

[ "${base}" ] || exit 1

echo "OpenSSL      $(openssl version 2>/dev/null | grep -Eo -m 1 ' [0-9]+.[0-9]+.[0-9a-z]+')"
echo "osslsigncode $(osslsigncode -v 2>/dev/null | grep -Eo -m 1 ' [0-9]+.[0-9]+.[0-9]+')"

# C  = Country
# L  = Locality
# ST = State
# O  = Organization
# CN = Common Name

readonly prfx="${base}_${revi}-"
readonly root="${prfx}ca"

echo '! Creating self-signed Root Certificate...'

# https://pki-tutorial.readthedocs.io/en/latest/simple/root-ca.conf.html
# https://en.wikipedia.org/wiki/X.509


if [ "$3" = 'rsa' ]; then
  cryptopt='-algorithm RSA -pkeyopt rsa_keygen_bits:4096'
else
  # TODO:
  #   https://github.com/openssl/openssl/pull/9223
  #     -pkeyopt ecdsa_nonce_type:deterministic
  cryptopt='-algorithm EC  -pkeyopt ec_paramgen_curve:secp384r1 -pkeyopt ec_param_enc:named_curve'
fi

# "$(pwgen --secure 40 1)"
readonly root_pass="$(openssl rand 32 | base58)"
privout "${root}.password" \
printf '%s' "${root_pass}"

# PKCS #8 private key, encrypted, PEM format.
# shellcheck disable=SC2086
openssl genpkey ${cryptopt} -aes-256-cbc -pass "pass:${root_pass}" -out "${root}-private.pem" 2>/dev/null
privout "${root}-private.pem.asn1.txt" \
openssl asn1parse -i -in "${root}-private.pem"
# openssl pkey -in "${root}-private.pem" -passin "pass:${root_pass}" -text -noout -out "${root}-private.pem.txt"

# -cert.pem is certificate (public key + subject + signature)
openssl req -batch -verbose -new -sha256 -x509 -days 1826 -passin "pass:${root_pass}" -key "${root}-private.pem" -out "${root}-cert.pem" -config - << EOF
[req]
encrypt_key = yes
prompt = no
utf8 = yes
string_mask = utf8only
distinguished_name = dn
x509_extensions = v3_ca

[v3_ca]
subjectKeyIdentifier = hash
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign

[dn]
CN = ${compname} Root CA ${revi}
EOF
openssl x509 -in "${root}-cert.pem" -text -noout -nameopt utf8 -sha256 -fingerprint > "${root}-cert.pem.x509.txt"
openssl asn1parse -i -in "${root}-cert.pem" > "${root}-cert.pem.asn1.txt"

# subordinates (don't set exactly the same 'subject' data as above)

# subordinate #1: code signing

readonly code="${prfx}code"

cat << EOF > "${code}-csr.config"
[req]
encrypt_key = yes
prompt = no
utf8 = yes
string_mask = utf8only
distinguished_name = dn
req_extensions = v3_req

[v3_req]
subjectKeyIdentifier = hash
keyUsage = critical, digitalSignature
# msCodeInd = Microsoft Individual Code Signing
# msCodeCom = Microsoft Commercial Code Signing
extendedKeyUsage = critical, codeSigning, msCodeInd

[dn]
CN = ${compname} Code Signing Authority
EOF

echo '! Creating Code Signing Certificate...'

# "$(pwgen --secure 40 1)"
readonly code_pass="$(openssl rand 32 | base58)"
privout "${code}.password" \
printf '%s' "${code_pass}"

# PKCS #8 private key, encrypted, PEM format.
# shellcheck disable=SC2086
openssl genpkey ${cryptopt} -aes-256-cbc -pass "pass:${code_pass}" -out "${code}-private.pem" 2>/dev/null
privout "${code}-private.pem.asn1.txt" \
openssl asn1parse -i -in "${code}-private.pem"
# Do not dump a decrypted private key
# openssl pkey -in "${code}-private.pem" -passin "pass:${code_pass}" -text -noout -out "${code}-private.pem.txt"

openssl pkey -passin "pass:${code_pass}" -in "${code}-private.pem" -pubout > "${code}-public.pem"
# Play some with the public key
openssl pkey -pubin -in "${code}-public.pem" -text -noout > "${code}-public.pem.txt"
openssl asn1parse -i -in "${code}-public.pem" > "${code}-public.pem.asn1.txt"

# -csr.pem is certificate signing request
openssl req -batch -verbose -new -sha256 -passin "pass:${code_pass}" -key "${code}-private.pem" -out "${code}-csr.pem" -config "${code}-csr.config"
openssl req -batch -verbose -in "${code}-csr.pem" -text -noout -nameopt utf8 > "${code}-csr.pem.txt"
openssl asn1parse -i -in "${code}-csr.pem" > "${code}-csr.pem.asn1.txt"

# -cert.pem is certificate (public key + subject + signature)
openssl x509 -req -sha256 -days 1095 \
  -extfile "${code}-csr.config" -extensions v3_req \
  -in "${code}-csr.pem" -passin "pass:${root_pass}" \
  -CA "${root}-cert.pem" -CAkey "${root}-private.pem" -CAcreateserial -out "${code}-cert.pem"
openssl x509 -in "${code}-cert.pem" -text -noout -nameopt utf8 -sha256 -fingerprint > "${code}-cert.pem.x509.txt"
openssl asn1parse -i -in "${code}-cert.pem" > "${code}-cert.pem.asn1.txt"

# You can include/exclude the root certificate by adding/removing option: `-chain -CAfile "${root}-cert.pem"`
# PKCS #12 .p12 is private key and certificate(-chain), encrypted
openssl pkcs12 -export \
  -keypbe aes-256-cbc -certpbe aes-256-cbc -macalg sha256 \
  -passout "pass:${code_pass}" \
  -passin "pass:${code_pass}" -inkey "${code}-private.pem" \
  -in "${code}-cert.pem" \
  -chain -CAfile "${root}-cert.pem" \
  -out "${code}.p12"
# `-nokeys` option avoids dumping unencrypted private key (kept the output private anyway)
openssl pkcs12 -passin "pass:${code_pass}" -in "${code}.p12" -info -nodes -nokeys -out "${code}.p12.txt"
privout "${code}.p12.asn1.txt" \
openssl asn1parse -i -inform DER -in "${code}.p12"

# "$(pwgen --secure 40 1)"
# Make sure password does not start with '/'. Some tools can mistake it for
# an option.
readonly encr_pass="$(openssl rand 32 | base58)"
privout "${code}.p12.gpg.password" \
printf '%s' "${encr_pass}"

# Encrypted .p12 for distribution (ASCII, binary)
gpg --batch --verbose --yes --passphrase "${encr_pass}" \
  --cipher-algo aes256 --digest-algo sha512 \
  --s2k-cipher-algo aes256 --s2k-digest-algo sha512 \
  --compress-algo none \
  --set-filename '' \
  --output "${code}.p12.asc" --armor \
  --symmetric "${code}.p12" \

gpg --batch --verbose --yes --passphrase "${encr_pass}" \
  --cipher-algo aes256 --digest-algo sha512 \
  --s2k-cipher-algo aes256 --s2k-digest-algo sha512 \
  --compress-algo none \
  --set-filename '' \
  --output "${code}.p12.gpg" \
  --symmetric "${code}.p12"

echo '! Test signing an executable...'

# Code signing for Windows

# Recreate minimal (runnable) PE executable.
# Dump created using:
#   curl --user-agent '' --doh-url "${MY_DOH_NUL}" \
#     -L https://web.archive.org/web/phreedom.org/research/tinype/tiny.c.1024/tiny.exe \
#   | gzip -n9 \
#   | openssl base64 -e > mk.sh
#   # SHA-256: 9d5efce48ed68dcb4caaa7fbecaf47ce2cab0a023afc6ceed682d1d532823773
cat << EOF | openssl base64 -d | gzip -d > test.exe
H4sIAAAAAAACA/ONmsDAzMDAwALE//8zMOxggAAHBsJgAxDzye/iY9jCeVZxB6PP
WcWQjMxihYKi/PSixFyF5MS8vPwShaRUhaLSPIXMPAUX/2CF3PyUVD1eXi4VqBk/
dYtu7vWR6YLhWV2FXXvAdAqYDspMzgCJw+wMcGVg8GFkZMjf6+oKE3vAwMzIzcjB
wMCE5DgBKFaA+gbEZoL4k4EBQYPlofog0gIQtXAaTg0o0CtJrSiBuRvqFxT/QryS
QKq5WVoRhxlGwYgFAPfKgYsABAAA
EOF

readonly test="${4:-test.exe}"

if [ -f "${test}" ]; then

  find . -name "${test%.exe}-signed*.exe" -delete

  readonly ts='https://tsa.swisssign.net'

  # using osslsigncode

  # - osslsigncode is not deterministic and it will also include all
  #   certificates from the .p12 file.
  #   It will always use `Microsoft Individual Code Signing`, regardless
  #   of the `extendedKeyUsage` value in the signing certificate. Can
  #   switch to Commercial by passing `-comm` option.
  # - signtool appears to be deterministic and will exclude the root
  #   certificate. Root (and intermediate) cert(s) can be added via
  #   -ac option.
  #   It will honor the Commercial/Individual info in `extendedKeyUsage`.
  #   if both are specified, it will be Commercial,
  #   if none, it will be Individual.
  #   Ref: https://docs.microsoft.com/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms537364(v=vs.85)#signcode

  temp='./_code.p12'
  rm -f "${temp}"
  gpg --batch --passphrase "${encr_pass}" --output "${temp}" --decrypt "${code}.p12.asc"

  case "$(uname)" in
    Darwin*|*BSD) unixts="$(TZ=UTC stat -f '%m'       "${test}")";;
    *)            unixts="$(TZ=UTC stat --format '%Y' "${test}")";;
  esac

  osslsigncode sign -h sha256 \
    -in "${test}" -out "${test%.exe}-signed-ossl-ts-1.exe" \
    -ts "${ts}" \
    -pkcs12 "${temp}" -pass "${code_pass}"

  osslsigncode sign -h sha256 \
    -in "${test}" -out "${test%.exe}-signed-ossl-1.exe" \
    -st "${unixts}" \
    -pkcs12 "${temp}" -pass "${code_pass}"
  sleep 3
  osslsigncode sign -h sha256 \
    -in "${test}" -out "${test%.exe}-signed-ossl-2.exe"  \
    -st "${unixts}" \
    -pkcs12 "${temp}" -pass "${code_pass}"

  rm -f "${temp}"

  # osslsigncode is non-deterministic, even if not specifying a timestamp
  # server, because openssl PKCS #7 code will unconditionally include the
  # local timestamp inside a `signingTime` PKCS #7 record.
  if diff --report-identical-files --binary \
       "${test%.exe}-signed-ossl-1.exe" \
       "${test%.exe}-signed-ossl-2.exe" >/dev/null; then
    echo '! Info: osslsigncode code signing: deterministic'
  else
    echo '! Info: osslsigncode code signing: non-deterministic'
  fi

  # using signtool.exe

  if [ "${os}" = 'win' ]; then

    # Root CA may need to be installed as a "Trust Root Certificate".
    # It has to be confirmed on a GUI dialog:
    #   certutil.exe -addStore -user -f 'Root' "${root}-cert.pem"

    cp "${test}" "${test%.exe}-signed-ms-ts.exe"
    signtool.exe sign -fd sha256 \
      -f "${code}.pfx" -p "${code_pass}" \
      -td sha256 -tr "${ts}" \
      "${test%.exe}-signed-ms-ts.exe"

    cp "${test}" "${test%.exe}-signed-ms-1.exe"
    signtool.exe sign -fd sha256 \
      -f "${code}.pfx" -p "${code_pass}" \
      "${test%.exe}-signed-ms-1.exe"
    sleep 3
    cp "${test}" "${test%.exe}-signed-ms-2.exe"
    signtool.exe sign -fd sha256 \
      -f "${code}.pfx" -p "${code_pass}" \
      "${test%.exe}-signed-ms-2.exe"

    # Remove root CA:
    #   certutil.exe -delStore -user 'Root' "$(openssl x509 -noout -subject -in "${root}-cert.pem" | sed -n '/^subject/s/^.*CN=//p')"

    # signtool.exe is deterministic, unless we specify a timestamp server
    if diff --report-identical-files --binary \
         "${test%.exe}-signed-ms-1.exe" \
         "${test%.exe}-signed-ms-2.exe" >/dev/null; then
      echo '! Info: signtool.exe code signing: deterministic'
    else
      echo '! Info: signtool.exe code signing: non-deterministic'
    fi
  fi

  if osslsigncode verify -CAfile "${root}-cert.pem" "${test}" 2>/dev/null | grep -q 'Signature verification: ok'; then
    echo "! Fail: unsigned exe passes: ${test}"
  else
    echo "! OK: unsigned exe fails: ${test}"
  fi

  for file in "${test%.exe}"-*.exe; do

    # Dump PKCS #7 signature record as PEM and as human-readable text
    osslsigncode extract-signature \
      -in "${file}" -pem -out "${file}.pkcs7" >/dev/null
    openssl asn1parse -i -inform PEM -in "${file}.pkcs7" > "${file}.pkcs7.asn1.txt" || true

    # Verify signature with osslsigncode
    if osslsigncode verify -CAfile "${root}-cert.pem" "${file}" 2>/dev/null | grep -q 'Signature verification: ok'; then
      echo "! OK: signed exe passes 'osslsigncode verify': ${file}"
    else
      echo "! Fail: signed exe fails 'osslsigncode verify': ${file}"
    fi

    unset wine
    [ "${os}" = 'win' ] || wine=wine

    if [ "${os}" = 'win' ]; then
      # TODO: verify using `signtool.exe verify`

      # Verify signature with sigcheck
      if "${wine}" sigcheck64.exe -nobanner -accepteula "${file}"; then
        # If we haven't specified a timestamp server when code signing,
        # sigcheck will report the _current time_ as "Signing date".
        echo "! OK: signed exe passes 'sigcheck64.exe': ${file}"
      else
        echo "! Fail: signed exe fails 'sigcheck64.exe': ${file}"
      fi
    fi
  done
else
  echo "! Error: '${test}' not found."
fi
