#!/usr/bin/env bash
if [ "$#" -ne 2 ]; then
	echo "gppro_upload.sh <AID> <CAP file>" >&2
	exit 1
fi

java -jar gp.jar -deletedeps -verbose -delete $1
java -jar gp.jar -install $2 -verbose -d


