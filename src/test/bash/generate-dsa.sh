#!/bin/bash -i

# Uses pem-jwk available
# npm install -g pem-jwk

function dsa () {
    DSA=${1?Specify the DSA bits}
    SHA=${2?Specify the SHA bits}

    # Step1. Create private/public keypair

    ## generates a pkcs1 private key and openssh public key
    echo "Generate DSA ssh-key of $DSA bits"
    ssh-keygen -b $DSA -t dsa -f private.pkcs1.pem -N ""

    # Step2. Convert it to every format imaginable

    echo "...private to pkcs8 der"
    openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pkcs1.pem -nocrypt > private.pkcs8.der
    echo "...private to pkcs8 pem"
    openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private.pkcs1.pem -out private.pkcs8.pem
    echo "...private to jwk"
    cat private.pkcs1.pem | pem-jwk > private.jwk

    mv private.pkcs1.pem.pub public.openssh
    echo "...public to pkcs1 pem"
    ssh-keygen -e -m PEM -f public.openssh > public.pkcs1.pem
    echo "...public to pkcs8 pem"
    ssh-keygen -e -m PKCS8 -f public.openssh > public.pkcs8.pem
    echo "...public to ssh2"
    ssh-keygen -e -m RFC4716 -f public.openssh > public.ssh2
    echo "...public to pkcs8 der"
    openssl dsa -in private.pkcs1.pem -pubout -outform DER > public.pkcs8.der
    #echo "...public to jwk"
    #cat public.pkcs1.pem | pem-jwk > public.jwk

    # Step 3.  Get fingerprint of the key

    ssh-keygen -lf public.openssh | perl -pe 's/.*SHA256:([^ ]+) .*/$1/' > fingerprint.txt

    # Step2. Create random data

    cat /dev/random | base64 | head -c $[ 11 + $[ RANDOM % 547 ]] > data.txt

    # Step3. Sign the data.txt using the private key

    openssl dgst -sha$SHA -sign private.pkcs8.pem data.txt | base64 > signature.txt
}

for algo in dsa; do
for bits in 1024 2048; do
for sha in 1 384 256 512; do

dir="${algo}${bits}-sha${sha}"
[ -d "dir" ] && rm -r "dir"
mkdir "$dir" && (cd "$dir" && dsa $bits $sha; )

done; done
done