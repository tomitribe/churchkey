#!/bin/bash

cat /dev/random | base64 | head -c $[ 11 + $[ RANDOM % 547 ]] > data.txt

for n in $(openssl ecparam -list_curves | tr ':' '\t' | cut -f 1 ); do

#     echo Create a key that uses the oid
#     openssl ecparam -name $n -genkey -noout -out private.pkcs1.$n.oid.pem
#     openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private.pkcs1.$n.oid.pem -out private.pkcs8.$n.oid.pem
#
#     echo Create a key that uses explicit parameters
#     openssl ecparam -name $n -genkey -noout -out private.pkcs1.$n.params.pem  -param_enc explicit
#     openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private.pkcs1.$n.params.pem -out private.pkcs8.$n.params.pem

    openssl dgst -sha256 -sign private.pkcs8.$n.params.pem data.txt | base64 > private.pkcs8.$n.params.sig
    echo

done
