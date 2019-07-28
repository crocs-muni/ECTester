#!/usr/bin/env bash

# Spell checker
# reset && hunspell -l -X chXX.xml | sort | uniq -i

# Name without extensions. The final artifact include PDF.
BOOKNAME=ectester

if [[ ! $(command -v xmllint) ]]
then
    echo "xmllint is not installed. Skipping validation."
    echo "  You can install libxml2-util for the program."
fi 

if [[ ! $(command -v xsltproc) ]]
then
    echo "xsltproc is not installed. Exiting."
    echo "  You must install libxml2-util for the program."
    exit 1
fi 

if [[ ! $(command -v fop) ]]
then
    echo "fop is not installed. Exiting."
    echo " You must install fop for the program."
    exit 1
fi 

if [[ $(command -v xmllint) ]]
then

    echo "Validating book..."
    if ! xmllint --xinclude --noout --postvalid book.xml
    then
        echo "Validation failed. Exiting."
        exit 1
    fi

    echo "Formatting source code..."
    for file in *.xml
    do
	if xmllint --format "$file" --output "$file.format"
        then
            mv "$file.format" "$file"
        fi
    done
fi

echo "Translating document..."
if ! xsltproc --xinclude custom.xsl book.xml > "$BOOKNAME.fo"
then
    echo "Failed to create Formatted Object."
    exit 1
fi

echo "Creating PDF..."
if ! fop -fo "$BOOKNAME.fo" -c fonts.xml -pdf "$BOOKNAME.pdf"
then
    echo "Failed to create PDF."
    exit 1
else
    rm "$BOOKNAME.fo" &>/dev/null
fi

echo "Created PDF $BOOKNAME.pdf."
cp "$BOOKNAME.pdf" ../

exit 0

