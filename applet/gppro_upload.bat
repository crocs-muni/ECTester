if "%1" == "" {
	set err=yes
}
if "%2" == "" {
	set err=yes
}
if "%err" == "yes" {
	echo "gppro_upload.bat <AID> <CAP file>"
	exit
}
gp.exe -deletedeps -verbose -delete %1
gp.exe -install %2 -verbose -d


