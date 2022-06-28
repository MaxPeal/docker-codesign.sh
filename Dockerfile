FROM alpine:3.16 AS BUILDER
# openssl 1.1.x, gpg, osslsigncode 2.1.0, GNU tail, base58
RUN apk add -u openssl3 gnupg coreutils py3-pip
RUN pip install base58
# libssl1.1 
RUN apk add -u cmake libssl3 libcurl curl-dev

WORKDIR /usr/src/app
ADD https://github.com/mtrojnar/osslsigncode/releases/download/2.3/osslsigncode-2.3.0.tar.gz
ADD https://github.com/mtrojnar/osslsigncode/releases/download/2.3/osslsigncode-2.3.0.tar.gz.asc
RUN tar xvzf osslsigncode-2.3.0.tar.gz --strip-components 1 -C $WORKDIR
#RUN tar xvzf osslsigncode-2.3.0.tar.gz --strip-components 1 -C osslsigncode
#WORKDIR /opt/osslsigncode
RUN mkdir build && cd build && cmake ..
RUN cmake --build .
RUN ctest -C Release
#RUN sudo cmake --install . --prefix "/user/local/bin"
RUN sudo cmake --install . --prefix "$WORKDIR/rootfs/"

FROM alpine:3.16 as IMAGE
#COPY --form builder
COPY --from=BUILDER /usr/src/app/rootfs/ /

WORKDIR /opt
ADD contrib/codesign.sh /opt
