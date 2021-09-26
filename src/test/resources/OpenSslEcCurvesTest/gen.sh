#!/bin/bash

for n in $(openssl ecparam -list_curves | tr ':' '\t' | cut -f 1 ); do
    echo $n;
    echo export the parameters
    openssl ecparam -name $n -out $n-params.pem -param_enc explicit

    echo export the oid
    openssl ecparam -name $n -out $n-oid.pem

    echo

done
