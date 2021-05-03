#!/bin/bash

SERVER_CERT_PATH="cert_files/server.pem"
SERVER_KEY_PATH="cert_files/server.key"
PORT=$1

if [ "$PORT" = "" ]; then
    echo "Since no port is given, defaulting to 4433"
    PORT=4433
fi

if ! [ -f $SERVER_CERT_PATH ]; then
    echo "Generating server keys and cert"
    mkdir -p cert_files
    openssl req \
        -x509 \
        -newkey rsa:4096 \
        -keyout $SERVER_KEY_PATH \
        -out $SERVER_CERT_PATH \
        -days 365 \
        -subj '/CN=selfsignedservercert'

    echo "Removing passphrase from key"
    openssl rsa \
        -in $SERVER_KEY_PATH \
        -out tmp.key
    rm $SERVER_KEY_PATH
    mv tmp.key $SERVER_KEY_PATH
else
    echo "Cert already existing. Skipping generation"
fi

echo "Starting TLS server on port $PORT"
openssl s_server \
    -cert $SERVER_CERT_PATH \
    -key $SERVER_KEY_PATH \
    -accept $PORT \
    -verify 3 \
    -msg \
    -www
