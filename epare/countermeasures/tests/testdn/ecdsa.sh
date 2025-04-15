if [[ ${3} == "install" ]]; then 
	java -jar ../../../../gp.jar --uninstall ../../../../applet/build/javacard/applet222.cap;    
	java -jar ../../../../gp.jar --install ../../../../applet/build/javacard/applet222.cap;    
fi


if [[ ${3} == "keyinstall" ]]; then 
	java -jar ../../../../gp.jar --uninstall ../../../../applet/build/javacard/applet222.cap -key 404142434445464748494A4B4C4D4E4F404142434445464748494A4B4C4D4E4F;    
	java -jar ../../../../gp.jar --install ../../../../applet/build/javacard/applet222.cap -key 404142434445464748494A4B4C4D4E4F404142434445464748494A4B4C4D4E4F;    

fi

java -jar ../../../../reader/build/libs/ECTesterReader.jar -ecdsa $2 -fp -b 256 -c weakcurve_32_n_2.csv -priv key.csv -pub key_point.csv -o ../../results/$1/testdn/ecdsa_n_2.csv | tee ../../results/$1/testdn/ecdsa_n_2.txt
