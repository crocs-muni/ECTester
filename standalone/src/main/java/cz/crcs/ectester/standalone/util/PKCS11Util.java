package cz.crcs.ectester.standalone.util;

import cz.crcs.ectester.common.util.FileUtil;

import java.io.File;
import java.io.IOException;

public class PKCS11Util {

    public static final String PKCS11_RESOURCES_PATH = "/cz/crcs/ectester/standalone/libs/pkcs11/";

    public static String getAbsoluteResourcePath(String resourcePath) {
        try {
            File tmp = File.createTempFile("ECTester-pkcs11-lib-", FileUtil.getLibSuffix());
            tmp.deleteOnExit();
            if (FileUtil.write(PKCS11_RESOURCES_PATH + resourcePath, tmp.toPath())) {
                return tmp.getAbsolutePath();
            }

            return null;
        } catch (IOException e) {
            System.err.println(e.getMessage());
            return null;
        }
    }
}
