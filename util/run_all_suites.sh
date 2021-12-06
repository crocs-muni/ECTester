#!/usr/bin/bash
#
# ECTesterStandalone testing script,
# runs all the suites on all the libraries
#
tempfolder=.temp_results
cur=$PWD
cd "$(dirname "${BASH_SOURCE[0]}")"/../dist
run="$(which java) -jar ECTesterStandalone-dist.jar"
suites=$($run list-suites | grep -P "^ -" | cut -c3-)
cd $cur

rm -rf $tempfolder
mkdir $tempfolder
while read -r suite; do
    echo "**Run $suite suite on all the libraries:"
    bash run_test_suite.sh $suite
    unzip results_$suite.zip -d $tempfolder
    rm results_$suite.zip
done <<< "$suites"

if [[ -f results_all.zip ]]; then
    echo '**Removing old archive...'
    rm -f results_all.zip
fi
echo '**Creating archive...'
cd $tempfolder && zip -r ../results_all.zip . && cd ..
rm -rf $tempfolder
echo "**All tests finished! The results can be found in results_all.zip"
