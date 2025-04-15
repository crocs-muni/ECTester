if [[ ${3} == "install" ]]; then 
	java -jar ../../../gp.jar --uninstall ../../../applet/build/javacard/applet222.cap;    
	java -jar ../../../gp.jar --install ../../../applet/build/javacard/applet222.cap;    
fi


if [[ ${3} == "keyinstall" ]]; then 
	java -jar ../../../gp.jar --uninstall ../../../applet/build/javacard/applet222.cap -key 404142434445464748494A4B4C4D4E4F404142434445464748494A4B4C4D4E4F;    
	java -jar ../../../gp.jar --install ../../../applet/build/javacard/applet222.cap -key 404142434445464748494A4B4C4D4E4F404142434445464748494A4B4C4D4E4F;    

fi    

prime=373

java -jar ../../../reader/build/libs/ECTesterReader.jar -ecdsa $2 -fp -b 256 -c ../../curves/curves_small_generator_full/cofactor256p${prime}_small_generator_full.csv -o ../../cards/$1/testany/ecdsa_${prime}_$2.csv | tee ../../cards/$1/testany/ecdsa_${prime}_$2.txt

