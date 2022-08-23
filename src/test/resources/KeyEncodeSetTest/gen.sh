#!/bin/bash

echo "{
    \"keys\": [" 
for n in *.jwk; do
    cat $n
    echo ","
done
echo "]
}"


