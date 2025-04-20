#!/usr/bin/env bash

url=$1

if [[ -z $url ]]; then
    echo "Usage: ./scan.sh <URL>"
    exit 1
fi

directories=()

ffuf -u http://testphp.vulnweb.com/FUZZ -w ./wordlists/dirb/small.txt -s > directories.txt

while IFS= read -r line; do
    echo $line
    directories+=$line
done < directories.txt

for d in "${directories[@]}"; do 
    echo "$d"

    echo "Starting the scan for $d"
    curl -X POST http://localhost:8080/scan \
        -H "Content-Type: application/json" \
        -d '{"url": "'"$url/$d"'"}'
done
