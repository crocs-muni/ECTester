#!/usr/bin/bash
#
# ECTesterStandalone testing script,
# runs the specified suite on all installed libraries
#
suite=${1,,}
extra_args="" #e.g., -kt ECDH -st ECDSA
tempfolder="temp_results"
cur=$PWD
timeout=10

cd "$(dirname "${BASH_SOURCE[0]}")"/../dist
if [[ $# -eq 0 ]]; then
    echo 'No test suite specified.'
    exit 0
fi
if [[ ! -f ECTesterStandalone-dist.jar ]]; then
    echo 'ECTesterStandalone-dist.jar not found. Build ECTesterStandalone first.'
    exit 0
fi

rm -rf $tempfolder
mkdir $tempfolder
run="$(which java) -jar ECTesterStandalone-dist.jar"
libs=$($run list-libs | grep -P "^\t-" | cut -d"-" -f 2 | cut -d"(" -f1)
while read -r lib; do
    if [[ $lib == *"BoringSSL"* ]]; then
        lib=BoringSSL
    fi
    mkdir -p $tempfolder/${suite}/$"${lib// /_}"
    filename=$tempfolder/${suite}/$"${lib// /_}"/results.txt

    echo "Testing library: $lib..."
    #Botan and Crypto++ don't recognize default kgt type EC, specify kgt=ECDH instead.
    if [[ $lib == *"Botan"* ]] || [[ $lib == *"Crypto++"* ]]; then
        args="-gt ECDH"
    else
        args=""
    fi

    #Wrong suite can cause a freeze in some libraries. Try running the tests again with the -skip argument if it happens. Default timeout is 10s.
    if [[ $suite == "wrong" ]]; then
        timeout ${timeout}s $run test $args $extra_args $suite "$lib" > $filename 2>&1
        if [[ $? -eq 124 ]]; then
                echo "#" >> $filename
                echo "# NOTE: Tests timeouted at this point after taking longer than ${timeout}s. What follows next is a second run with -skip argument." >> $filename
                echo "#" >> $filename
                $run test $args $extra_args $suite -skip "$lib" >> $filename 2>&1
        fi
    #Composite suite can also cause a freeze, but this time there is no -skip argument.
    elif [[ $suite == "composite" ]]; then
        timeout ${timeout}s $run test $args $extra_args $suite "$lib" > $filename 2>&1
        if [[ $? -eq 124 ]]; then
                echo "#" >> $filename
                echo "# NOTE: Tests timeouted at this point after taking longer than ${timeout}s." >> $filename
                echo "#" >> $filename
        fi
    #Signature suite requires SHA1withECDSA signature type
    elif [[ $suite == "signature" ]]; then
        $run test $args $extra_args -st SHA1withECDSA $suite "$lib" > $filename 2>&1
    else
        $run test $args $extra_args $suite "$lib" > $filename 2>&1
    fi
done <<< "$libs"

#Comment out these two lines to keep java error logs. They are removed by default to prevent unnecessary cluttering of dist folder.
echo 'Removing java error logs...'
find . -type f -name 'hs_err_*' -exec rm {} \;

if [[ -f $cur/results_$suite.zip ]]; then
    echo 'Removing old archive...'
    rm -f $cur/results_$suite.zip
fi
echo 'Creating archive...'
cd $tempfolder
zip -r $cur/results_$suite.zip .
cd ..
rm -rf $tempfolder

echo "Finished. The results can be found in results_$suite.zip."
exit 1
