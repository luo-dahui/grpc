#!/bin/bash

# SSL_CMD=openssl
SSL_CMD=$HOME/.local/GMTASSL/bin/gmtassl

# Certificate Authority (CA)
$SSL_CMD genrsa -passout pass:123456 -out ca-secret.key 4096
$SSL_CMD rsa -passin pass:123456 -in ca-secret.key -out ca.key
$SSL_CMD req -new -x509 -days 3650 -subj '/C=CN/L=ShenZhen/O=GRPC Root CA/OU=GRPC CA unit/CN=root' -key ca.key -out ca.crt
$SSL_CMD pkcs12 -export -passout pass:123456 -inkey ca.key -in ca.crt -out ca.pfx
$SSL_CMD pkcs12 -passin pass:123456 -passout pass:123456 -in ca.pfx -out ca.pem

# SSL Server certificate
$SSL_CMD genrsa -passout pass:123456 -out server-secret.key 4096
$SSL_CMD rsa -passin pass:123456 -in server-secret.key -out server.key
#$SSL_CMD req -new -subj '/C=CN/L=ShenZhen/O=GRPC SSL IO Server/OU=GRPC server unit/CN=localhost' -key server.key -out server.csr
$SSL_CMD req -new -key server.key -out server.csr -config server_cert.conf
$SSL_CMD x509 -req -days 3650 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt -extfile server_cert.conf -extensions req_ext
$SSL_CMD pkcs12 -export -passout pass:123456 -inkey server.key -in server.crt -out server.pfx
$SSL_CMD pkcs12 -passin pass:123456 -passout pass:123456 -in server.pfx -out server.pem

# SSL Client certificate
$SSL_CMD genrsa -passout pass:123456 -out client-secret.key 4096
$SSL_CMD rsa -passin pass:123456 -in client-secret.key -out client.key
$SSL_CMD req -new -subj '/C=CN/L=ShenZhen/O=GRPC SSL IO Client/OU=GRPC client unit/CN=client' -key client.key -out client.csr
$SSL_CMD x509 -req -days 3650 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out client.crt
$SSL_CMD pkcs12 -export -passout pass:123456 -inkey client.key -in client.crt -out client.pfx
$SSL_CMD pkcs12 -passin pass:123456 -passout pass:123456 -in client.pfx -out client.pem

# Diffie Hellman (D-H) key exchange (if necessary)
# $SSL_CMD dhparam -out dh4096.pem 4096

# SSL Server certificate
# $SSL_CMD genrsa -out server-prikey 4096
# $SSL_CMD req -new -subj '/C=CN/L=ShenZhen/O=GRPC SSL IO server/OU=GRPC server unit/CN=server' -key server-prikey -out cert.req
# $SSL_CMD x509 -req -days 365 -in cert.req -signkey server-prikey -out server-nopass.cert

# remove pfx key csr crt
#rm -rf *.pfx *.crt *.key *.csr *.req
# rm -rf *.pfx *.crt *.csr *.req *secret.key
rm -rf *.pfx *.csr *.req *secret.key
