
#ARG target=build_osslsigncode_releases
#ARG target=imageout
FROM alpine:3.16 AS builder
ARG target

# build with cache invalide at ARG dateVAR
# docker buildx build . --progress plain --build-arg dateVAR=$(date +%s) --tag codesign.sh
# docker buildx build . --progress plain --tag codesign.sh --load && docker run --rm -it codesign.sh
# docker buildx build . --progress plain --tag codesign.sh:imageout --target imageout  --load && docker run --rm -it codesign.sh:releases
# docker buildx build . --progress plain --tag codesign.sh:gitmaster --target build_osslsigncode_gitmaster --load

# docker buildx build . --progress plain --tag codesign.sh:releases --target build_osslsigncode_releases  --load && docker run --rm -it codesign.sh:releases
# docker buildx build . --progress plain --tag codesign.sh:ac --target build_osslsigncode_gitmaster_ac  --load && docker run --rm -it codesign.sh:ac 

# docker buildx build . --progress plain  --tag codesignsh --tag codesignsh:ac --target build_osslsigncode_gitmaster_ac --load && docker run --rm -it codesignsh:ac

# docker buildx build . --progress plain  --tag codesignsh --tag codesignsh:image --load && docker run --rm -it codesignsh:image

# docker buildx build . --progress plain  --tag codesignsh:latest --tag codesignsh:image --target build_osslsigncode_git_ac --target build_osslsigncode_archive  --target build_osslsigncode_gitmaster --target imageout --load && docker run --rm -it codesignsh:image


# docker buildx build . --progress plain  --tag codesignsh:latest --tag codesignsh:image --target build_osslsigncode_git_ac --target build_osslsigncode_archive  --target build_osslsigncode_git --target imageout --load && docker run --rm -it codesignsh:image

# add @testing /testing repository and @community /community
RUN cp -p /etc/apk/repositories /etc/apk/repositories.org && \
	echo "https://dl-cdn.alpinelinux.org/alpine/v$(cut -d'.' -f1,2 /etc/alpine-release)/main/" | tee /etc/apk/repositories && \
	echo "https://dl-cdn.alpinelinux.org/alpine/v$(cut -d'.' -f1,2 /etc/alpine-release)/community/" | tee -a /etc/apk/repositories && \
	echo "### @community https://dl-cdn.alpinelinux.org/alpine/v$(cut -d'.' -f1,2 /etc/alpine-release)/community/" | tee -a /etc/apk/repositories && \
	echo "@testing https://dl-cdn.alpinelinux.org/alpine/edge/testing/" | tee -a /etc/apk/repositories ###&& \
##	grep -v /devnull /etc/apk/repositories
RUN apk add -u libfaketime@testing
#	$(echo) https://dl-cdn.alpinelinux.org/alpine/v$(cut -d'.' -f1,2 /etc/alpine-release)/main/
# dont work # RUN cat > /etc/apk/repositories << EOF; $(echo) 
# dont work # https://dl-cdn.alpinelinux.org/alpine/v$(cut -d'.' -f1,2 /etc/alpine-release)/main/
# dont work # @community https://dl-cdn.alpinelinux.org/alpine/v$(cut -d'.' -f1,2 /etc/alpine-release)/community/
# dont work # @testing https://dl-cdn.alpinelinux.org/alpine/edge/testing/
# dont work # EOF

# https://stackoverflow.com/questions/68996420/how-to-set-timezone-inside-alpine-base-docker-image
# https://wiki.alpinelinux.org/wiki/Alpine_Linux:FAQ#How_do_I_set_the_local_timezone.3F
# https://gitlab.alpinelinux.org/alpine/aports/-/issues/5543
# https://developpaper.com/perfect-solution-to-docker-alpine-image-time-zone-problem/
RUN apk add -U tzdata && ln -s /usr/share/zoneinfo/Europe/Berlin /etc/localtime
# date && ntpd -d -q -n -p uk.pool.ntp.org
##ENV TZ=Europe/Berlin
## RUN cp /usr/share/zoneinfo/Europe/Berlin /etc/localtime


# openssl 1.1.x, gpg, osslsigncode 2.1.0, GNU tail, base58
#RUN apk add -u openssl3 gnupg coreutils tar file findutils py3-pip
RUN apk add -u openssl3 openssl gnupg coreutils tar file findutils
###RUN apk add -u py3-pip && pip install base58
# libssl1.1 
#RUN apk add -u cmake libssl3 libcurl curl-dev autoconf automake libtool build-base alpine-sdk
#RUN apk add -u build-base alpine-sdk curl-dev openssl3-dev autoconf2.13
# for osslsigncode
RUN apk add -u build-base alpine-sdk curl-dev openssl-dev autoconf autoconf-archive libtool automake cmake pythonispython3 libfaketime@testing bash
# for libbase58
RUN apk add -u build-base alpine-sdk curl-dev openssl-dev autoconf autoconf-archive libtool automake libgcrypt-dev


ENV user core
#RUN useradd -d /home/$user -m -s /bin/bash $user
RUN NEWUSER="$user" ; busybox adduser -D "${NEWUSER}" $NEWUSER
RUN apk add sudo && NEWUSER="$user" ; echo "$NEWUSER ALL=(ALL) ALL" > /etc/sudoers.d/$NEWUSER && chmod 0440 /etc/sudoers.d/$NEWUSER
#RUN apk add -U bash sudo && echo "$user ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$user
#RUN chmod 0440 /etc/sudoers.d/$user
###USER $user



FROM builder AS build_libbase58
WORKDIR /usr/src/
ADD https://github.com/luke-jr/libbase58/archive/b1dd03fa8d1be4be076bb6152325c6b5cf64f678.tar.gz /usr/src/libbase58.tar.gz
RUN find /usr/src -ls
ARG dateVAR
##RUN tar -xvzf /usr/src/libbase58.tar.gz --strip-components=1 --show-transformed-names --show-stored-names  -C ./app/
RUN mkdir -p app/ && tar -xvzf libbase58.tar.gz --strip-components=1 -C app/
RUN find /usr/src -ls
WORKDIR /usr/src/app/
ENV CONFIGURE_OPTS="--enable-tool --enable-static --enable-shared"
ENV MAKE_CHECK=1
RUN ./autogen.sh
RUN ./configure $CONFIGURE_OPTS || tail -n 1000 config.log
RUN make
RUN test -z "$MAKE_CHECK" || make check
RUN make install DESTDIR=$PWD/ii
RUN cd ii && find
ARG target
#ENV target
ENV target=$target
RUN echo target $target and targetVAR $targetVAR
#RUN echo $targetVAR



FROM builder AS build_osslsigncode_releases
ENV targetVAR=build_osslsigncode_releases
WORKDIR /usr/src/
ADD https://github.com/mtrojnar/osslsigncode/releases/download/2.3/osslsigncode-2.3.0.tar.gz /usr/src/osslsigncode.tar.gz
ADD https://github.com/mtrojnar/osslsigncode/releases/download/2.3/osslsigncode-2.3.0.tar.gz.asc /usr/src/osslsigncode.tar.gz.asc
RUN find /usr/src -ls
# https://www.gnu.org/software/tar/manual/html_section/transform.html
# Extract ‘usr/’ hierarchy into ‘usr/local/’: $ tar --transform='s,usr/,usr/local/,' -x -f arch.tar
# Strip two leading directory components (equivalent to ‘--strip-components=2’): $ tar --transform='s,/*[^/]*/[^/]*/,,' -x -f arch.tar
# transform first leading directory components to app: $ tar --transform='s,/*[^/]*/,app,' -x -f arch.tar
ARG dateVAR
### RUN tar -xvzf /usr/src/osslsigncode.tar.gz --transform='s,/*[^/]*/,app/,' --show-transformed --show-transformed-names
# FIXME not 100% working # RUN tar -xvzf osslsigncode.tar.gz --strip-components=1 --transform='s,[^/]*/,app/,g' --show-transformed --show-transformed-names
RUN mkdir -p app/ && tar -xvzf osslsigncode.tar.gz --strip-components=1 -C app/
RUN find /usr/src -ls
#RUN tar xvzf osslsigncode-2.3.0.tar.gz --strip-components 1 -C osslsigncode
#WORKDIR /opt/osslsigncode
WORKDIR /usr/src/app/
#RUN mkdir build && cd build && cmake ..
#RUN cmake --build .
#RUN ctest -C Release
#RUN sudo cmake --install . --prefix "/user/local/bin"
#RUN sudo cmake --install . --prefix "${WORKDIR}/rootfs/"
#RUN autoreconf -ifv && configure -with-curl && make build
#RUN ./autogen.sh && ./configure --prefix=/usr --mandir=/usr/share/man --sbindir=/usr/bin --bindir=/usr/bin && make build && make check && make DESTDIR=$PWD/rootfs install
#RUN ./autogen.sh && ./configure && make build && make check && make DESTDIR=$PWD/rootfs install
RUN ./configure && make && make check && make DESTDIR=$PWD/rootfs install
RUN find $PWD/rootfs -ls
ARG target
#ENV target
ENV target=$target
RUN echo target $target and targetVAR $targetVAR
#RUN echo $targetVAR

FROM builder AS build_osslsigncode_archive
ENV targetVAR=build_osslsigncode_archive
WORKDIR /usr/src/
ADD https://github.com/mtrojnar/osslsigncode/archive/2.3.tar.gz /usr/src/osslsigncode.tar.gz
RUN find /usr/src -ls
ARG dateVAR
RUN mkdir -p app/ && tar -xvzf osslsigncode.tar.gz --strip-components=1 -C app/
RUN find /usr/src -ls
WORKDIR /usr/src/app/
RUN ./bootstrap && ./configure && make && make check && make DESTDIR=$PWD/rootfs install
RUN find $PWD/rootfs -ls
ARG target
#ENV target
ENV target=$target
RUN echo target $target and targetVAR $targetVAR
#RUN echo $targetVAR


FROM builder AS build_osslsigncode_git_ac
ENV targetVAR=build_osslsigncode_git_ac
## apk add libgcab msitools mingw-w64-gcc
RUN apk add libgcab msitools mingw-w64-gcc xxd libgsf libgsf-dev vim grep coreutils libcurl curl libfaketime@testing libfaketime-doc@testing tz tzdata
WORKDIR /usr/src/
#ADD https://github.com/mtrojnar/osslsigncode/archive/2.3.tar.gz /usr/src/osslsigncode.tar.gz
ADD https://github.com/mtrojnar/osslsigncode/archive/b96717506c60af1c1af86f7f9ba1f1e1ac95a57e.tar.gz /usr/src/osslsigncode.tar.gz
# last commit bevor switch to cmake # ADD https://github.com/mtrojnar/osslsigncode/archive/b96717506c60af1c1af86f7f9ba1f1e1ac95a57e.tar.gz /usr/src/osslsigncode.tar.gz
RUN find /usr/src -ls
ARG dateVAR
RUN mkdir -p app/ && tar -xvzf osslsigncode.tar.gz --strip-components=1 -C app/
RUN find /usr/src -ls
WORKDIR /usr/src/app/
#RUN ./bootstrap && ./configure && make && make check && make DESTDIR=$PWD/rootfs install
RUN ./bootstrap 
RUN ./configure --with-curl
RUN make 
RUN make check
#### for run manuel # RUN find $PWD -ls && cd tests && bash testall.sh ||:
RUN make DESTDIR=$PWD/rootfs install
RUN find $PWD/rootfs -ls
ARG target
#ENV target
ENV target=$target
RUN echo target $target and targetVAR $targetVAR
#RUN echo $targetVAR


FROM builder AS build_osslsigncode_git
###COPY --from=build_libbase58 /usr/src/app/ii/ /
RUN apk add -u py3-pip && pip install base58
ENV targetVAR=build_osslsigncode_git
WORKDIR /usr/src/
# last commit bevor switch to cmake # ADD https://github.com/mtrojnar/osslsigncode/archive/b96717506c60af1c1af86f7f9ba1f1e1ac95a57e.tar.gz /usr/src/osslsigncode.tar.gz
## apk add libgcab msitools mingw-w64-gcc || mingw-w64-gcc-base
## apk add libgcab msitools mingw-w64-gcc xxd libgsf libgsf-dev vim grep coreutils libcurl curl libfaketime@testing libfaketime-doc@testing
ADD https://github.com/mtrojnar/osslsigncode/archive/860e8d6f4e2d6683f803fadc1ab17a6f5cdeb5db.tar.gz /usr/src/osslsigncode.tar.gz
RUN find /usr/src -ls
ARG dateVAR
RUN mkdir -p app/ && tar -xvzf osslsigncode.tar.gz --strip-components=1 -C app/
RUN find /usr/src -ls
WORKDIR /usr/src/app/
RUN mkdir build 
WORKDIR /usr/src/app/build
RUN cmake ..
RUN cmake --build .
RUN ctest -C Release ||:
###RUN ctest -C Release --rerun-failed --output-on-failure ||:
##RUN sudo cmake --install . --prefix "$PWD/../rootfs"
###RUN cmake --install . #--prefix "$PWD/rootfs" DESTDIR=$PWD/rootfs
#RUN cmake --install . --prefix /usr/src/rootfs/
#RUN cmake --install /usr/src/rootfs 
RUN make DESTDIR=/usr/src/app/rootfs install
RUN cmake --build . --target package_source
##RUN find $PWD/../rootfs -ls
RUN find /usr/src /usr/local -ls
ARG target
#ENV target
ENV target=$target
RUN echo target $target and targetVAR $targetVAR
#RUN echo $targetVAR


FROM alpine:3.16 as image
#COPY --form build1
# for osslsigncode
RUN apk add -u openssl curl scanelf bash
# for libbase58
RUN apk add -u libgcrypt
# for codesign.sh
RUN apk add -u gnupg coreutils diffutils
# COPY --from=build_osslsigncode_releases /usr/src/app/rootfs/ /
ARG target
#ENV target
ENV target=$target
RUN echo target $target and targetVAR $targetVAR
#RUN echo $target
#RUN echo $targetVAR
#COPY --from=build_osslsigncode:$"{target}" /usr/src/app/rootfs/ /
COPY --from=build_osslsigncode_releases /usr/src/app/rootfs/ /build_osslsigncode_releases/
COPY --from=build_osslsigncode_archive /usr/src/app/rootfs/ /build_osslsigncode_archive/
COPY --from=build_osslsigncode_git /usr/src/app/rootfs/ /build_osslsigncode_git/
COPY --from=build_osslsigncode_git_ac /usr/src/app/rootfs/ /build_osslsigncode_git_ac/
COPY --from=build_libbase58 /usr/src/app/ii/ /

RUN apk add -U findutils && find /usr/src /usr/local -ls ; find /build* -ipath "/build*" -ls
RUN mkdir -p /usr/local/bin &&ln -s /build_osslsigncode_git/usr/local/bin/osslsigncode /usr/local/bin/osslsigncode 
RUN mkdir -p /usr/local/share/bash-completion/completions/ && ln -s /build_osslsigncode_git_ac/usr/local/share/bash-completion/completions/osslsigncode.bash /usr/local/share/bash-completion/completions/osslsigncode.bash

FROM image as imageout
#WORKDIR /opt
ADD --chmod=755 contrib/codesign.sh /usr/local/bin/

# Recreate minimal (runnable) PE executable.
# Dump created using:
#   curl --user-agent '' --doh-url "${MY_DOH_NUL}" \
#     -L https://web.archive.org/web/phreedom.org/research/tinype/tiny.c.1024/tiny.exe \
#   | gzip -n9 \
#   | openssl base64 -e > mk.sh
#   # SHA-256: 9d5efce48ed68dcb4caaa7fbecaf47ce2cab0a023afc6ceed682d1d532823773
#RUN cat << EOF | openssl base64 -d | gzip -d > tiny.exe \
###RUN base64var="H4sIAAAAAAACA/ONmsDAzMDAwALE//8zMOxggAAHBsJgAxDzye/iY9jCeVZxB6PPWcWQjMxihYKi/PSixFyF5MS8vPwShaRUhaLSPIXMPAUX/2CF3PyUVD1eXi4VqBk/dYtu7vWR6YLhWV2FXXvAdAqYDspMzgCJw+wMcGVg8GFkZMjf6+oKE3vAwMzIzcjBwMCE5DgBKFaA+gbEZoL4k4EBQYPlofog0gIQtXAaTg0o0CtJrSiBuRvqFxT/QrySQKq5WVoRhxlGwYgFAPfKgYsABAAA" \
###cat << EOF | openssl base64 -d | gzip -d > tiny.exe


#cat << EOF | openssl base64 -d | gzip -d > test.exe
#H4sIAAAAAAACA/ONmsDAzMDAwALE//8zMOxggAAHBsJgAxDzye/iY9jCeVZxB6PP
#WcWQjMxihYKi/PSixFyF5MS8vPwShaRUhaLSPIXMPAUX/2CF3PyUVD1eXi4VqBk/
#dYtu7vWR6YLhWV2FXXvAdAqYDspMzgCJw+wMcGVg8GFkZMjf6+oKE3vAwMzIzcjB
#wMCE5DgBKFaA+gbEZoL4k4EBQYPlofog0gIQtXAaTg0o0CtJrSiBuRvqFxT/QryS
#QKq5WVoRhxlGwYgFAPfKgYsABAAA
#EOF


ENV user core
RUN NEWUSER="$user" ; busybox adduser -D "${NEWUSER}" $NEWUSER
# no sudo # RUN apk add sudo && NEWUSER="$user" ; echo "$NEWUSER ALL=(ALL) ALL" > /etc/sudoers.d/$NEWUSER && chmod 0440 /etc/sudoers.d/$NEWUSER
WORKDIR /home/$user
USER $user
#USER nobody
RUN openssl base64 -d <<EOF | gzip -d > tiny.exe
H4sIAAAAAAACA/ONmsDAzMDAwALE//8zMOxggAAHBsJgAxDzye/iY9jCeVZxB6PP
WcWQjMxihYKi/PSixFyF5MS8vPwShaRUhaLSPIXMPAUX/2CF3PyUVD1eXi4VqBk/
dYtu7vWR6YLhWV2FXXvAdAqYDspMzgCJw+wMcGVg8GFkZMjf6+oKE3vAwMzIzcjB
wMCE5DgBKFaA+gbEZoL4k4EBQYPlofog0gIQtXAaTg0o0CtJrSiBuRvqFxT/QryS
QKq5WVoRhxlGwYgFAPfKgYsABAAA
EOF


CMD /bin/sh -vx -c "osslsigncode --version ; codesign.sh tiny.exe"

