#!/bin/bash

for n in $(openssl ecparam -list_curves | tr ':' '\t' | cut -f 1 ); do
    echo $n;
    echo export the parameters
    openssl ecparam -name $n -out $n-params.pem -param_enc explicit

    echo export the oid
    openssl ecparam -name $n -out $n-oid.pem

    echo Create a key that uses the oid
    openssl ecparam -name $n -genkey -noout -out openssl-ecprivatekey-$n.pkcs1.pem
    openssl pkcs8 -topk8 -nocrypt -in openssl-ecprivatekey-$n.pkcs1.pem -out openssl-ecprivatekey-$n.pem

    echo Create a key that uses explicit parameters
    openssl ecparam -name $n -genkey -noout -out openssl-ecprivatekey-$n.pkcs1.pem  -param_enc explicit
    echo
done
