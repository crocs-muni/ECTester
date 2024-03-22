if "%1" == "" {
	set err=yes
}
if "%2" == "" {
	set err=yes
}
if "%err" == "yes" {
	echo "gppro_upload_emv.bat <AID> <CAP file>"
	exit
}

gp.exe -deletedeps -verbose -emv -delete %1
gp.exe -install %2 -verbose  -emv -d


