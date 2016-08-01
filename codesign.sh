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
#   OpenSSL 1.x, gpg, pwgen (or apg), osslsigncode
# Mac:
#   brew install openssl gnupg pwgen osslsigncode apg
# Win:
#   pacman -S openssl gnupg pwgen mingw-w64-{i686,x86_64}-osslsigncode
#   sigcheck64.exe:
#      curl -O https://live.sysinternals.com/tools/sigcheck64.exe
#   signtool.exe:
#      part of Windows SDK

# - .pem is a format, like .der
# - .crt/.cer denote a certificate or multiple certificates
# - .pub is a public key (usually in PEM or DER format, but it may also exist
#                         in one-liner OpenSSH key format RFC 4251)
# - .key is a private key (usually in PEM or DER format)
# - .srl is certificate serial number
# - .pfx is Microsoft name for .p12
#           = PKCS #12 = encrypted certificate(s) + private keys.
#           Strictly PKCS #12-compliant systems (like MS/Apple tools) only
#           understand weakly encrypted, standard .p12 files. OpenSSL-based
#           tools (like osslsigncode) will accept modern crypto algos as well.
#           Fun read: https://www.cs.auckland.ac.nz/~pgut001/pubs/pfx.html
# - .pvk is Microsoft proprietary Private Key format, encrypted (weak crypto)
# - .spc is Microsoft name for .p7b (PKCS #7) = Software Publisher Certificate
#           (or Certificate Bundle), internally it's DER format and contains
#           certificates

case "$(uname)" in
   *Darwin*)
      readonly os='mac'
      # Need to make this a function instead of an `alias`
      # to make it work as expected when passed to `privout`
      openssl() {
         /usr/local/opt/openssl/bin/openssl "$@"
      };;
   *_NT*)  PATH=/mingw64/bin:${PATH}; readonly os='win';;
   linux*) readonly os='linux';;
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

readonly base='test_'

readonly dc0='com'
readonly dc1='example'
readonly country='NET'
readonly location='Earth'
readonly compname='Example'

openssl version

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
privout "${root}.passwd" \
echo "${root_pass}"

# PKCS #8 is private key, encrypted. TODO: replace `-v2 aes-256-cbc` with `-scrypt` @ OpenSSL 1.1.0
openssl genrsa 4096 2> /dev/null | \
privout "${root}_private.key" \
openssl pkcs8 -topk8 -v2 aes-256-cbc -passout "pass:${root_pass}"
privout "${root}_private.key.asn.txt" \
openssl asn1parse -in "${root}_private.key"
# privout "${root}_private.key.rsa.txt" \
# openssl rsa       -in "${root}_private.key" -passin "pass:${root_pass}" -text -noout

# .crt is certificate (public key + subject + signature)
openssl req -batch -verbose -new -sha256 -x509 -days 1826 -passin "pass:${root_pass}" -key "${root}_private.key" -out "${root}.crt" -config "${root}.csr.config"
openssl x509 -in "${root}.crt" -text -noout -nameopt utf8 -sha256 -fingerprint > "${root}.crt.txt"

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
extendedKeyUsage = critical, codeSigning, msCodeInd, msCodeCom

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
privout "${code}.passwd" \
echo "${code_pass}"

# PKCS #8 is private key, encrypted. TODO: replace `-v2 aes-256-cbc` with `-scrypt` @ OpenSSL 1.1.0
openssl genrsa 4096 2> /dev/null | \
privout "${code}_private.key" \
openssl pkcs8 -topk8 -v2 aes-256-cbc -passout "pass:${code_pass}"
privout "${code}_private.key.asn.txt" \
openssl asn1parse -in "${code}_private.key"
# Do not dump a decrypted private key
#   privout "${code}_private.key.rsa.txt" \
#   openssl rsa       -in "${code}_private.key" -passin "pass:${code_pass}" -text -noout
openssl rsa -passin "pass:${code_pass}" -in "${code}_private.key" -pubout > "${code}_public.key"

# .csr is certificate signing request
openssl req -batch -verbose -new -sha256 -passin "pass:${code_pass}" -key "${code}_private.key" -out "${code}.csr" -config "${code}.csr.config"
openssl req -batch -verbose -in "${code}.csr" -text -noout -nameopt utf8 > "${code}.csr.txt"

# .crt is certificate (public key + subject + signature)
openssl x509 -req -sha256 -days 1095 \
   -extfile "${code}.csr.config" -extensions v3_req \
   -in "${code}.csr" -passin "pass:${root_pass}" \
   -CA "${root}.crt" -CAkey "${root}_private.key" -CAcreateserial -out "${code}.crt"
openssl x509 -in "${code}.crt" -text -noout -nameopt utf8 -sha256 -fingerprint > "${code}.crt.txt"

# You can include/exclude the root certificate by adding/removing option: `-chain -CAfile "${root}.crt"`
# PKCS #12 .p12 is private key and certificate(-chain), encrypted
privout "${code}.p12" \
openssl pkcs12 -export \
   -keypbe aes-256-cbc -certpbe aes-256-cbc -macalg sha256 \
   -passout "pass:${code_pass}" \
   -passin "pass:${code_pass}" -inkey "${code}_private.key" \
   -in "${code}.crt" \
   -chain -CAfile "${root}.crt"
# `-nokeys` option will avoid dumping unencrypted private key (kept the output private anyway)
privall "${code}.p12.txt" \
openssl pkcs12 -passin "pass:${code_pass}" -in "${code}.p12" -info -nodes -nokeys

# "$(apg -m 32 -x 32 -n 1 -M NCL)"
readonly encr_pass="$(pwgen -s 32 1)"
privout "${code}.p12.gpg.passwd" \
echo "${encr_pass}"

# Encrypted .p12.gpg for distribution
gpg --batch -v --yes --passphrase "${encr_pass}" \
   --cipher-algo AES256 --digest-algo SHA512 \
   --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 \
   --output "${code}.p12.gpg" -c "${code}.p12"

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
   -passin "pass:${code_pass}" -inkey "${code}_private.key" \
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
openssl rsa -outform PVK -passout "pass:${code_pass}" -passin "pass:${code_pass}" -in "${code}_private.key"
# "${code}.pvk.txt" should be identical to "${code}_private.key.rsa.txt"
#   privout "${code}.pvk.txt" \
#   openssl rsa -inform PVK -passin "pass:${code_pass}" -in "${code}.pvk" -text -noout

# .spc is certificate(-chain)

# Same as below, but using the .p12 as the input:
#   temp="$(mktemp -t X)"
#   openssl pkcs12 -passin "pass:${code_pass}" -in "${code}.p12" -nokeys > "${temp}"
#   openssl crl2pkcs7 -nocrl -certfile "${temp}" -outform DER -out "${code}.spc"
#   rm -f "${temp}"

openssl crl2pkcs7 -certfile "${code}.crt" -certfile "${root}.crt" -nocrl -outform DER -out "${code}.spc"
openssl pkcs7 -inform DER -in "${code}.spc" -print_certs -text -noout > "${code}.spc.txt"

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
   # - signtool appears to be deterministic and will exclude the root
   #   certificate. Root (and intermediate) cert(s) can be added via
   #   -ac option.

   temp='./_code.p12'
   gpg --batch --passphrase "${encr_pass}" -o "${temp}" -d "${code}.p12.gpg"

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
   # local timestamp.
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
      #   certutil.exe -delstore -user 'Root' "$(openssl x509 -noout -subject -in "${root}.crt" | sed -n '/^subject/s/^.*CN=//p')"

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
      if osslsigncode verify "${file}" 2> /dev/null | grep 'Signature verification: ok' > /dev/null ; then
         echo "! OK: signed exe passes osslsigncode verify: ${file}"
      else
         echo "! Fail: signed exe fails osslsigncode verify: ${file}"
      fi
      if [ "${os}" = 'win' ] ; then
         # sigcheck will report the current time as "Signing date",
         # if we haven't specified a timestamp server when code signing.
         if sigcheck64.exe -nobanner -accepteula "${file}" ; then
            echo "! OK: signed exe passes sigcheck64.exe: ${file}"
         else
            echo "! Fail: signed exe fails sigcheck64.exe: ${file}"
         fi
      fi
   done
else
   echo "! Error: '${test}' not found."
fi
