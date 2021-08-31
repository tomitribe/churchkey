#!/bin/bash -x

# Uses pem-jwk available
# npm install -g pem-jwk

function gen () {
    BITS=${1?Specify the key bits}

    # private.openssh
    ssh-keygen -b $BITS -t ecdsa -f private.openssh -N ""

    # public.openssh
    mv private.openssh.pub public.openssh

    # private.pkcs1.pem
    cp private.openssh private.pkcs1.pem
    ssh-keygen -p -N "" -m pem -f private.pkcs1.pem

    # private.pkcs8.der
    openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pkcs1.pem -nocrypt > private.pkcs8.der

    # private.pkcs8.pem
    openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private.pkcs1.pem -out private.pkcs8.pem

    # public.pkcs8.pem
    ssh-keygen -e -m PKCS8 -f public.openssh > public.pkcs8.pem
    
    # public.ssh2
    ssh-keygen -e -m RFC4716 -f public.openssh > public.ssh2

    # public.pkcs8.der
    openssl ec -in private.pkcs1.pem -pubout -outform DER > public.pkcs8.der

    # Get fingerprint of the key
    ssh-keygen -lf public.openssh | perl -pe 's/.*SHA256:([^ ]+) .*/$1/' > fingerprint.txt

    # Create random data
    cat /dev/random | base64 | head -c $[ 11 + $[ RANDOM % 547 ]] > data.txt

    # Sign the data.txt using the private key

    openssl dgst -sha256 -sign private.pkcs8.pem data.txt | base64 > signature-sha256.txt
    openssl dgst -sha512 -sign private.pkcs8.pem data.txt | base64 > signature-sha512.txt

}

for algo in ecdsa-nistp; do
for bits in 256 384 521; do

dir="${algo}${bits}"
[ -d "dir" ] && rm -r "dir"
mkdir "$dir" && (cd "$dir" && gen $bits; )

done
done
