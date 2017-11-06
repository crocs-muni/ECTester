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

if [[ $# -lt 1 ]]; then
    echo "At least one argument expected:" >&2
    echo "    ./ectester.sh [--dangerous] CARD_NAME [ECTester args]" >&2
    exit 1
fi

card="$1"
shift

declare -a tests=("default" "test-vectors")
if [[ "$dangerous" == "1" ]]; then
    tests+=("invalid" "wrong" "composite")
fi

declare -a files=()
for i in $(seq 0 $((${#tests[@]} - 1))); do
    test="${tests[$i]}"
    java -jar ECTester.jar -t ${test} -a --format yaml -l ${card}.${test} $@
    files+=(${card}.$test)
done

if command -v tar 2>&1 >/dev/null; then
    tar -czvf ${card}.tar.gz ${files[*]}
elif command -v zip 2>&1 >/dev/null; then
    zip ${card}.zip ${files[*]}
fi
