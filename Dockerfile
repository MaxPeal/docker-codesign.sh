FROM alpine:3.16 AS builder
# openssl 1.1.x, gpg, osslsigncode 2.1.0, GNU tail, base58
RUN apk add -u openssl3 gnupg coreutils py3-pip
RUN pip install base58
# libssl1.1 
RUN apk add -u cmake libssl3 libcurl curl-dev

FROM builder AS build1
WORKDIR /usr/src
ADD https://github.com/mtrojnar/osslsigncode/releases/download/2.3/osslsigncode-2.3.0.tar.gz $WORKDIR/osslsigncode.tar.gz
ADD https://github.com/mtrojnar/osslsigncode/releases/download/2.3/osslsigncode-2.3.0.tar.gz.asc $WORKDIR/osslsigncode.tar.gz.asc
WORKDIR /usr/src/app
RUN tar xvzf ../osslsigncode.tar.gz --strip-components 1 -C $WORKDIR
#RUN tar xvzf osslsigncode-2.3.0.tar.gz --strip-components 1 -C osslsigncode
#WORKDIR /opt/osslsigncode
RUN mkdir build && cd build && cmake ..
RUN cmake --build .
RUN ctest -C Release
#RUN sudo cmake --install . --prefix "/user/local/bin"
RUN sudo cmake --install . --prefix "$WORKDIR/rootfs/"

FROM builder AS build2
WORKDIR /usr/src
ADD https://github.com/luke-jr/libbase58/archive/b1dd03fa8d1be4be076bb6152325c6b5cf64f678.tar.gz $WORKDIR/libbase58.tar.gz
WORKDIR /usr/src/app
RUN tar xvzf ../libbase58.tar.gz --strip-components 1 -C $WORKDIR
ENV CONFIGURE_OPTS="--enable-tool --enable-static --enable-shared"
ENV MAKE_CHECK=1
RUN ./autogen.sh
RUN ./configure $CONFIGURE_OPTS || tail -n 1000 config.log
RUN make
RUN test -z "$MAKE_CHECK" || make check
RUN make install DESTDIR=$PWD/ii
RUN cd ii && find

FROM alpine:3.16 as IMAGE
#COPY --form build1
COPY --from=build1 /usr/src/app/rootfs/ /
COPY --from=build2 /usr/src/app/ii/ /

WORKDIR /opt
ADD contrib/codesign.sh /opt
