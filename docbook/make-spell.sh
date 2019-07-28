#!/usr/bin/env bash

if [[ -z $(command -v hunspell) ]]
then
    echo "hunspell is not installed. Exiting."
    echo "  You can install hunspell for the program."
    exit 1
fi 

for file in *.xml
do
    echo "***************************************"
    echo "Spell checking $file"

    grep -o '<para>.*</para>' "$file" | \
        hunspell -d en_US -p book.dict -l -X | grep -v 0x | sort | uniq -i
    grep -o '<title>.*</title>' "$file" | \
        hunspell -d en_US -p book.dict -l -X | grep -v 0x | sort | uniq -i
done

exit 0

