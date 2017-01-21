#!/bin/sh -e

# To the extent possible under law, Viktor Szakats (vszakats.net)
# has waived all copyright and related or neighboring rights to this
# script.
# CC0 - https://creativecommons.org/publicdomain/zero/1.0/

# This script will create a self-signed root certificate, along with a code
# signing certificate in various formats, trying to use the best available
# crypto/practice all along. Then, it will create a test executable and code
# sign it using both osslsigncode and signtool.exe (on Windows only) and
# verify those signature using osslsigncode and sigcheck.exe (on Windows only).

# Requires:
#   OpenSSL 1.x, gpg, pwgen (or apg), osslsigncode, GNU tail
# Mac:
#   brew install openssl gnupg pwgen osslsigncode apg coreutils
# Win:
#   pacman -S openssl gnupg pwgen mingw-w64-{i686,x86_64}-osslsigncode
#   sigcheck64.exe:
#      curl -O https://live.sysinternals.com/tools/sigcheck64.exe
#   signtool.exe:
#      part of Windows SDK

# /usr/local/opt/openssl/bin/openssl list-cipher-algorithms
# /usr/local/opt/openssl@1.1/bin/openssl list -cipher-algorithms

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
      # Need to make this a function instead of an `alias`
      # to make it work as expected when passed to `privout`/`privall`
      if [ -f ./openssl ] ; then
         # Use local copy if present
         openssl() {
            ./openssl "$@"
         }
      else
         openssl() {
            /usr/local/opt/openssl@1.1/bin/openssl "$@"
         }
      fi
      tail() {
         gtail "$@"
      }
      if [ -f ./osslsigncode ] ; then
         # Use local copy if present
         osslsigncode() {
            ./osslsigncode "$@"
         }
      fi
      readonly os='mac';;
   *_NT*)
      # To find osslsigncode
      PATH=/mingw64/bin:${PATH}
      readonly os='win';;
   linux*)
      readonly os='linux';;
esac

# Redirect stdout securely to non-world-readable files
privout() {
   o="$1"; rm -f "$o"; touch "$o"; chmod 0600 "$o"; shift
   (
      "$@"
   ) >> "$o"
}

# Redirect all output securely to non-world-readable files
privall() {
   o="$1"; rm -f "$o"; touch "$o"; chmod 0600 "$o"; shift
   (
      "$@"
   ) >> "$o" 2>&1
}

# Extract PKCS #7 blob from MS Authenticode signature
#    https://www.cs.auckland.ac.nz/~pgut001/pubs/authenticode.txt
strip_signature_header() {
   tail -c +9 "$1" > "$1.truncated" && mv -f "$1.truncated" "$1"
}

readonly base='test_'

readonly dc0='com'
readonly dc1='example'
readonly country='NET'
readonly location='Earth'
readonly compname='Example'

echo "OpenSSL      $(openssl version 2> /dev/null | grep -Eo -m 1 ' [0-9]+.[0-9]+.[0-9a-z]+')"
echo "osslsigncode $(osslsigncode -v 2> /dev/null | grep -Eo -m 1 ' [0-9]+.[0-9]+.[0-9]+')"

# C  = Country
# L  = Locality
# ST = State
# O  = Organization
# OU = Organizational Unit
# CN = Common Name

readonly root="${base}CA"

echo '! Creating self-signed Root Certificate...'

# https://pki-tutorial.readthedocs.io/en/latest/simple/root-ca.conf.html
# https://en.wikipedia.org/wiki/X.509

cat << EOF > "${root}.csr.config"
[req]
encrypt_key = yes
prompt = no
utf8 = yes
string_mask = utf8only
distinguished_name = dn
x509_extensions = v3_ca

[v3_ca]
subjectKeyIdentifier = hash
basicConstraints = CA:TRUE
keyUsage = critical, keyCertSign, cRLSign

[dn]
#0.domainComponent = ${dc0}
#1.domainComponent = ${dc1}
#C = ${country}
#L = ${location}
O  = ${compname}
OU = ${compname} Root CA
CN = ${compname} Root CA
EOF

# "$(apg -m 32 -x 32 -n 1 -M NCL)"
readonly root_pass="$(pwgen -s 32 1)"
privout "${root}.password" \
echo "${root_pass}"

# TODO: add `-strictpem` option to all `openssl asn1parse` commands
#       where a PEM file is expected @ OpenSSL 1.1.0. Otherwise
#       openssl would also process the BEGIN/END separators, leading
#       to occasional processing errors.
#          https://github.com/openssl/openssl/issues/1381#issuecomment-237095795

# PKCS #8 private key, encrypted, PEM format.
privout "${root}_private.pem" \
openssl genpkey -algorithm RSA -aes-256-cbc -pkeyopt rsa_keygen_bits:4096 -pass "pass:${root_pass}" 2> /dev/null
privout "${root}_private.pem.asn1.txt" \
openssl asn1parse -i -in "${root}_private.pem"
# privout "${root}_private.pem.rsa.txt" \
# openssl rsa       -in "${root}_private.pem" -passin "pass:${root_pass}" -text -noout

# PKCS #8 private key, encrypted, DER format.
privout "${root}_private.der" \
openssl pkcs8 -topk8 -v2 aes-256-cbc -scrypt -passin "pass:${root_pass}" -in "${root}_private.pem" -outform DER -passout "pass:${root_pass}"
privout "${root}_private.der.asn1.txt" \
openssl asn1parse -i -inform DER -in "${root}_private.der"

# PKCS #8 private key, encrypted, PEM format (reconvert from DER).
privout "${root}_private2.pem" \
openssl pkcs8 -topk8 -v2 aes-256-cbc -scrypt -passin "pass:${root_pass}" -in "${root}_private.pem" -outform PEM -passout "pass:${root_pass}"
mv -f "${root}_private2.pem" "${root}_private.pem"
privout "${root}_private.pem.asn1.txt" \
openssl asn1parse -i -inform PEM -in "${root}_private.pem"

# .crt is certificate (public key + subject + signature)
openssl req -batch -verbose -new -sha256 -x509 -days 1826 -passin "pass:${root_pass}" -key "${root}_private.pem" -out "${root}.crt" -config "${root}.csr.config"
openssl x509 -in "${root}.crt" -text -noout -nameopt utf8 -sha256 -fingerprint > "${root}.crt.x509.txt"
openssl asn1parse -i -in "${root}.crt" > "${root}.crt.asn1.txt"

# subordinates (don't give exactly the same subject data as above)

# subordinate #1: code signing

readonly code="${base}code"

cat << EOF > "${code}.csr.config"
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
#0.domainComponent = ${dc0}
#1.domainComponent = ${dc1}
#C = ${country}
#L = ${location}
O  = ${compname}
OU = ${compname} Code Signing Authority
CN = ${compname} Code Signing Authority
EOF

echo '! Creating Code Signing Certificate...'

# "$(apg -m 32 -x 32 -n 1 -M NCL)"
readonly code_pass="$(pwgen -s 32 1)"
privout "${code}.password" \
echo "${code_pass}"

# PKCS #8 private key, encrypted, PEM format.
privout "${code}_private.pem" \
openssl genpkey -algorithm RSA -aes-256-cbc -pkeyopt rsa_keygen_bits:4096 -pass "pass:${code_pass}" 2> /dev/null
privout "${code}_private.pem.asn1.txt" \
openssl asn1parse -i -in "${code}_private.pem"
# Do not dump a decrypted private key
#   privout "${code}_private.pem.rsa.txt" \
#   openssl rsa       -in "${code}_private.pem" -passin "pass:${code_pass}" -text -noout

# PKCS #8 private key, encrypted, DER format.
privout "${code}_private.der" \
openssl pkcs8 -topk8 -v2 aes-256-cbc -scrypt -passin "pass:${code_pass}" -in "${code}_private.pem" -outform DER -passout "pass:${code_pass}"
privout "${code}_private.der.asn1.txt" \
openssl asn1parse -i -inform DER -in "${code}_private.der"

# PKCS #8 private key, encrypted, PEM format (reconvert from DER).
privout "${code}_private2.pem" \
openssl pkcs8 -topk8 -v2 aes-256-cbc -scrypt -passin "pass:${code_pass}" -in "${code}_private.pem" -outform PEM -passout "pass:${code_pass}"
mv -f "${code}_private2.pem" "${code}_private.pem"
privout "${code}_private.pem.asn1.txt" \
openssl asn1parse -i -inform PEM -in "${code}_private.pem"

openssl rsa -passin "pass:${code_pass}" -in "${code}_private.pem" -pubout > "${code}_public.pem"
# Play some with the public key
openssl rsa -pubin -in "${code}_public.pem" -text -noout > "${code}_public.pem.rsa.txt"
openssl asn1parse -i -in "${code}_public.pem" > "${code}_public.pem.asn1.txt"
openssl rsa -pubin -in "${code}_public.pem" -outform DER > "${code}_public.der"
openssl rsa -pubin -inform DER -in "${code}_public.der" -text -noout > "${code}_public.der.rsa.txt"
openssl asn1parse -i -inform DER -in "${code}_public.der" > "${code}_public.der.asn1.txt"

# .csr is certificate signing request
openssl req -batch -verbose -new -sha256 -passin "pass:${code_pass}" -key "${code}_private.pem" -out "${code}.csr" -config "${code}.csr.config"
openssl req -batch -verbose -in "${code}.csr" -text -noout -nameopt utf8 > "${code}.csr.txt"
openssl req -batch -verbose -in "${code}.csr" -outform DER > "${code}.csr.der"
openssl asn1parse -i -in "${code}.csr" > "${code}.csr.asn1.txt"

# .crt is certificate (public key + subject + signature)
openssl x509 -req -sha256 -days 1095 \
   -extfile "${code}.csr.config" -extensions v3_req \
   -in "${code}.csr" -passin "pass:${root_pass}" \
   -CA "${root}.crt" -CAkey "${root}_private.pem" -CAcreateserial -out "${code}.crt"
openssl x509 -in "${code}.crt" -text -noout -nameopt utf8 -sha256 -fingerprint > "${code}.crt.x509.txt"
openssl asn1parse -i -in "${code}.crt" > "${code}.crt.asn1.txt"

# You can include/exclude the root certificate by adding/removing option: `-chain -CAfile "${root}.crt"`
# PKCS #12 .p12 is private key and certificate(-chain), encrypted
privout "${code}.p12" \
openssl pkcs12 -export \
   -keypbe aes-256-cbc -certpbe aes-256-cbc -macalg sha256 \
   -passout "pass:${code_pass}" \
   -passin "pass:${code_pass}" -inkey "${code}_private.pem" \
   -in "${code}.crt" \
   -chain -CAfile "${root}.crt"
# `-nokeys` option avoids dumping unencrypted private key (kept the output private anyway)
privall "${code}.p12.txt" \
openssl pkcs12 -passin "pass:${code_pass}" -in "${code}.p12" -info -nodes -nokeys
privall "${code}.p12.asn1.txt" \
openssl asn1parse -i -inform DER -in "${code}.p12"

# "$(apg -m 32 -x 32 -n 1 -M NCL)"
readonly encr_pass="$(pwgen -s 32 1)"
privout "${code}.p12.gpg.password" \
echo "${encr_pass}"

# Encrypted .p12 for distribution (ASCII, binary)
gpg --batch -v --yes --passphrase "${encr_pass}" \
   --cipher-algo aes256 --digest-algo sha512 \
   --s2k-cipher-algo aes256 --s2k-digest-algo sha512 \
   --set-filename '' \
   --output "${code}.p12.asc" --armor \
   -c "${code}.p12" \

gpg --batch -v --yes --passphrase "${encr_pass}" \
   --cipher-algo aes256 --digest-algo sha512 \
   --s2k-cipher-algo aes256 --s2k-digest-algo sha512 \
   --set-filename '' \
   --output "${code}.p12.gpg" \
   -c "${code}.p12"

# Disable this, unsecure, no longer needed. Unless using Windows.
if [ "${os}" = 'win' ] ; then

echo '! Create Microsoft-specific Code Signing files...'

# .pfx is same as .p12 except in this one we use weak crypto to make it work
#         with signtool.exe
#
# Microsoft signtool.exe (as of Windows 10 SDK) and certmgr.msc UI will report
# "wrong password" if any of the modern encryption parameters is used.
# This is the best supported crypto: SHA1 + 3DES CBC (Iteration 2048)
#
# `-descert` option is the same as `-certpbe PBE-SHA1-3DES`
#   (casing is significant with the latter flavor)
# `-keysig` is optional, will limit this file for signing only.
#
# Reference:
#    https://www.mail-archive.com/openssl-users%40openssl.org/msg75443.html
privout "${code}.pfx" \
openssl pkcs12 -export \
   -keysig \
   -certpbe PBE-SHA1-3DES \
   -passout "pass:${code_pass}" \
   -passin "pass:${code_pass}" -inkey "${code}_private.pem" \
   -in "${code}.crt" \
   -chain -CAfile "${root}.crt"
# `-nokeys` will avoid dumping unencrypted private key (kept the output private anyway)
privall "${code}.pfx.txt" \
openssl pkcs12 -passin "pass:${code_pass}" -in "${code}.pfx" -info -nodes -nokeys

# .pvk is private key, encrypted
#   Requires OpenSSL 1.0.1 or upper to use the strongest available
#   encryption (-pvk-strong), which is still weak crypto.

# Same as below, but using the .p12 as the input:
#   openssl pkcs12 -passin "pass:${code_pass}" -in "${code}.p12" -nocerts -nodes | \
#   privout "${code}.pvk" \
#   openssl rsa -outform PVK -passout "pass:${code_pass}"

privout "${code}.pvk" \
openssl rsa -outform PVK -passout "pass:${code_pass}" -passin "pass:${code_pass}" -in "${code}_private.pem"
# "${code}.pvk.rsa.txt" should be identical to "${code}_private.pem.rsa.txt"
#   privout "${code}.pvk.rsa.txt" \
#   openssl rsa -inform PVK -passin "pass:${code_pass}" -in "${code}.pvk" -text -noout

# .spc is certificate(-chain)

# Same as below, but using the .p12 as the input:
#   temp="$(mktemp -t X)"
#   openssl pkcs12 -passin "pass:${code_pass}" -in "${code}.p12" -nokeys > "${temp}"
#   openssl crl2pkcs7 -nocrl -certfile "${temp}" -outform DER -out "${code}.spc"
#   rm -f "${temp}"

openssl crl2pkcs7 -certfile "${code}.crt" -certfile "${root}.crt" -nocrl -outform DER -out "${code}.spc"
openssl pkcs7 -inform DER -in "${code}.spc" -print_certs -text -noout > "${code}.spc.pkcs7.txt"
openssl asn1parse -i -inform DER -in "${code}.spc" > "${code}.spc.asn1.txt"

fi

echo '! Test signing an executable...'

# Code signing for Windows

# Recreate minimal (but already runnable) PE executable.
# Dump created using:
#   curl http://www.phreedom.org/research/tinype/tiny.c.1024/tiny.exe | \
#   gzip -cn9 test.exe | \
#   openssl base64 -e > mk.sh
cat << EOF | openssl base64 -d | gzip -cd > test.exe
H4sIAAAAAAACA/ONmsDAzMDAwALE//8zMOxggAAHBsJgAxDzye/iY9jCeVZxB6PP
WcWQjMxihYKi/PSixFyF5MS8vPwShaRUhaLSPIXMPAUX/2CF3PyUVD1eXi4VqBk/
dYtu7vWR6YLhWV2FXXvAdAqYDspMzgCJw+wMcGVg8GFkZMjf6+oKE3vAwMzIzcjB
wMCE5DgBKFaA+gbEZoL4k4EBQYPlofog0gIQtXAaTg0o0CtJrSiBuRvqFxT/QryS
QKq5WVoRhxlGwYgFAPfKgYsABAAA
EOF

readonly test="${1:-test.exe}"

if [ -f "${test}" ] ; then

   find . -name "${test%.exe}-signed*.exe" -delete

   readonly ts='http://timestamp.digicert.com'

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
   #   Ref: https://msdn.microsoft.com/library/ms537364#SignCode

   temp='./_code.p12'
   gpg --batch --passphrase "${encr_pass}" -o "${temp}" -d "${code}.p12.asc"

   osslsigncode sign -h sha256 \
      -pkcs12 "${temp}" -pass "${code_pass}" \
      -ts "${ts}" \
      -in "${test}" -out "${test%.exe}-signed-ossl-ts-1.exe"

   osslsigncode sign -h sha256 \
      -pkcs12 "${temp}" -pass "${code_pass}" \
      -in "${test}" -out "${test%.exe}-signed-ossl-1.exe"
   sleep 3
   osslsigncode sign -h sha256 \
      -pkcs12 "${temp}" -pass "${code_pass}" \
      -in "${test}" -out "${test%.exe}-signed-ossl-2.exe"

   rm -f "${temp}"

   # osslsigncode is non-deterministic, even if not specifying a timestamp
   # server, because openssl PKCS #7 code will unconditionally include the
   # local timestamp inside a `signingTime` PKCS #7 record.
   if diff -s --binary "${test%.exe}-signed-ossl-1.exe" "${test%.exe}-signed-ossl-2.exe" > /dev/null ; then
      echo '! Info: osslsigncode code signing: deterministic'
   else
      echo '! Info: osslsigncode code signing: non-deterministic'
   fi

   # using signtool.exe

   if [ "${os}" = 'win' ] ; then

      # Root CA may need to be installed as a "Trust Root Certificate".
      # It has to be confirmed on a GUI dialog:
      #   certutil.exe -addStore -user -f 'Root' "${root}.crt"

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
      #   certutil.exe -delStore -user 'Root' "$(openssl x509 -noout -subject -in "${root}.crt" | sed -n '/^subject/s/^.*CN=//p')"

      # signtool.exe is deterministic, unless we specify a timestamp server
      if diff -s --binary "${test%.exe}-signed-ms-1.exe" "${test%.exe}-signed-ms-2.exe" > /dev/null ; then
         echo '! Info: signtool.exe code signing: deterministic'
      else
         echo '! Info: signtool.exe code signing: non-deterministic'
      fi
   fi

   if osslsigncode verify "${test}" 2> /dev/null | grep 'Signature verification: ok' > /dev/null ; then
      echo "! Fail: unsigned exe passes: ${test}"
   else
      echo "! OK: unsigned exe fails: ${test}"
   fi

   for file in ${test%.exe}-*.exe ; do

      # TODO: Replace `strip_signature_header` with `-pem` osslsigncode option
      #       @ osslsigncode above 1.7.1

      # Dump PKCS #7 signature record as DER and as human-readable text
      osslsigncode extract-signature \
         -in "${file}" -out "${file}.pkcs7" > /dev/null
      strip_signature_header "${file}.pkcs7"
      openssl asn1parse -i -inform DER -in "${file}.pkcs7" > "${file}.pkcs7.asn1.txt" || true

      # Verify signature with osslsigncode
      if osslsigncode verify "${file}" 2> /dev/null | grep 'Signature verification: ok' > /dev/null ; then
         echo "! OK: signed exe passes 'osslsigncode verify': ${file}"
      else
         echo "! Fail: signed exe fails 'osslsigncode verify': ${file}"
      fi

      if [ "${os}" = 'win' ] ; then

         # TODO: verify using `signtool.exe verify`

         # Verify signature with sigcheck
         if sigcheck64.exe -nobanner -accepteula "${file}" ; then
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
