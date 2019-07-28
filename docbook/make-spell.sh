#!/usr/bin/env bash

if [[ ! $(command -v hunspell) ]]
then
    echo "hunspell is not installed. Exiting."
    echo "  You can install hunspell for the program."
    [[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 1 || return 1
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

[[ "$0" = "${BASH_SOURCE[0]}" ]] && exit 0 || return 0

