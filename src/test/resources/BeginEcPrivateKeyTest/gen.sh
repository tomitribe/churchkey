#!/bin/bash

for n in $(openssl ecparam -list_curves | tr ':' '\t' | cut -f 1 ); do

    echo Create a key that uses the oid
    openssl ecparam -name $n -genkey -noout -out private.pkcs1.$n.oid.pem

    echo Create a key that uses explicit parameters
    openssl ecparam -name $n -genkey -noout -out private.pkcs1.$n.params.pem  -param_enc explicit

    echo

done
