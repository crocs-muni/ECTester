#!/usr/bin/env bash
#
# ECTesterStandalone testing script,
# tests to see everything is implemented correctly in the testing tool
#
cur=$PWD
cd "$(dirname "${BASH_SOURCE[0]}")"/../dist

trap int INT
function int() {
    cd $cur
    exit 1
}

function do_test() {
    out=$($run "$@")
    ret=$?
    echo "$out" | tail -n1
    if [ "$ret" -ne "0" ]; then
        echo ">>>> ERROR '$@' => $ret"
    fi
}

run="$(which java) -jar ECTesterStandalone.jar"
libs=$($run list-libs | grep -P "^\t-" | cut -d"-" -f 2 | cut -d"(" -f1)
while read -r lib; do
    echo "** Testing library: $lib"
    support=$($run list-libs "$lib")
    kpgs=$(echo "$support" | grep KeyPairGenerators | cut -d":" -f2 | sed 's/,//g')
    kas=$(echo "$support" | grep KeyAgreements | cut -d":" -f2 | sed 's/,//g')
    sigs=$(echo "$support" | grep Signatures | cut -d":" -f2 | sed 's/,//g')
    for kpg in $kpgs; do
        echo "*** KPG: $kpg"
        do_test generate -t $kpg "$lib"
    done
    for ka in $kas; do
        echo "*** KA: $ka"
        do_test ecdh -t $ka "$lib"
    done
    for sig in $sigs; do
        echo "*** SIG: $sig"
        do_test ecdsa -t $sig "$lib"
    done
    echo -en "\n\n"
done <<< "$libs"

trap INT
cd $cur