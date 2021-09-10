#!/bin/bash

for n in $(openssl ecparam -list_curves | tr ':' '\t' | cut -f 1 ); do
    openssl ecparam -name $n -genkey -noout -out openssl-ecprivatekey-$n.pkcs1.pem
    openssl pkcs8 -topk8 -nocrypt -in openssl-ecprivatekey-$n.pkcs1.pem -out openssl-ecprivatekey-$n.pem
    openssl pkcs8 -topk8 -nocrypt -in openssl-ecprivatekey-$n.pem -param_enc explicit -out openssl-ecprivatekey-$n-params.pem
    echo $n;
done
