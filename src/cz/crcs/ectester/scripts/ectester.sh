#!/bin/bash

dangerous="0"

positional=()
while [[ $# -gt 0 ]]
do

key="$1"
case $key in
    --dangerous)
    dangerous=1
    shift
    ;;
    *)
    positional+=("$1")
    shift
    ;;
esac
done
set -- "${positional[@]}"

if [[ $# -ne 1 ]]; then
    echo "One argument expected:" >&2
    echo "    ./ectester.sh [--dangerous] CARD_NAME" >&2
    exit 1
fi

declare -a tests=("default" "test-vectors")
if [[ "$dangerous" == "1" ]]; then
    tests+=("invalid" "wrong" "composite")
fi

declare -a files=()
for i in $(seq 0 $((${#tests[@]} - 1))); do
    test="${tests[$i]}"
    java -jar ECTester.jar -t ${test} -a --format yaml -l ${1}.${test}
    files+=(${1}.$test)
done

if command -v tar 2>&1 >/dev/null; then
    tar -czvf ${1}.tar.gz ${files[*]}
elif command -v zip 2>&1 >/dev/null; then
    zip ${1}.zip ${files[*]}
fi