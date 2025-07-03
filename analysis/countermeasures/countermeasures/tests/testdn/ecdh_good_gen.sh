if [[ ${3} == "install" ]]; then 
	java -jar ../../../gp.jar --uninstall ../../../applet/build/javacard/applet222.cap;    
	java -jar ../../../gp.jar --install ../../../applet/build/javacard/applet222.cap;    
fi


if [[ ${3} == "keyinstall" ]]; then 
	java -jar ../../../gp.jar --uninstall ../../../applet/build/javacard/applet222.cap -key 404142434445464748494A4B4C4D4E4F404142434445464748494A4B4C4D4E4F;    
	java -jar ../../../gp.jar --install ../../../applet/build/javacard/applet222.cap -key 404142434445464748494A4B4C4D4E4F404142434445464748494A4B4C4D4E4F;    

fi


java -jar ../../../reader/build/libs/ECTesterReader.jar -dh $2 -ka DH_PLAIN -fp -b 256 -c weakcurve_32_n_good_gen.csv --external -priv key.csv -pub weakcurve_32_n_1_point.csv -o ../../cards/$1/testdn/good_gen_$2.csv | tee ../../cards/$1/testdn/good_gen_$2.txt

