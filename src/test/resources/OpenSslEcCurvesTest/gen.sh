#!/bin/bash

for n in $(openssl ecparam -list_curves | tr ':' '\t' | cut -f 1 ); do

j=$(lc "$n" | perl -pe 's,-,,g')
cat <<EOF
    @Test
    public void ${j}Oid() throws Exception {
        assertCurveOid("${n}", Curve.${j});
    }

EOF

done
exit

j=$(lc "$n" | perl -pe 's,-,,g')
cat <<EOF
    @Test
    public void ${j}ParameterSpec() throws Exception {
        assertCurveParameterSpec("${n}", Curve.${j});
    }

EOF

done
exit

for n in $(openssl ecparam -list_curves | tr ':' '\t' | cut -f 1 ); do
    echo $n;
    echo export the parameters
    openssl ecparam -name $n -out $n-params.pem -param_enc explicit

    echo export the oid
    openssl ecparam -name $n -out $n-oid.pem

    echo Create a key that uses the oid
    openssl ecparam -name $n -genkey -noout -out openssl-ecprivatekey-$n.pkcs1.pem
    openssl pkcs8 -topk8 -nocrypt -in openssl-ecprivatekey-$n.pkcs1.pem -out openssl-ecprivatekey-$n-oid.pem

    echo Sign with the key that uses the oid
    openssl dgst -sha256 -sign openssl-ecprivatekey-$n-oid.pem data.txt | base64 > openssl-ecprivatekey-$n-oid.sig

    echo Create a key that uses explicit parameters
    openssl ecparam -name $n -genkey -noout -out openssl-ecprivatekey-$n-params.pem  -param_enc explicit

    echo Sign with the key that uses explicit parameters
    openssl dgst -sha256 -sign openssl-ecprivatekey-$n-params.pem data.txt | base64 > openssl-ecprivatekey-$n-params.sig

    echo

done
