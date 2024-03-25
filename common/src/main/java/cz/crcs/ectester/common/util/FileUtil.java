package cz.crcs.ectester.common.util;

import cz.crcs.ectester.common.output.TeeOutputStream;

import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class FileUtil {
    private static Path appData = null;
    public static String LIB_RESOURCE_DIR = "/cz/crcs/ectester/standalone/libs/jni/";

    public static OutputStream openStream(String[] files) throws FileNotFoundException {
        if (files == null) {
            return null;
        }
        List<OutputStream> outs = new LinkedList<>();
        for (String fileOut : files) {
            outs.add(new FileOutputStream(fileOut));
        }
        return new TeeOutputStream(outs.toArray(new OutputStream[0]));
    }

    public static OutputStreamWriter openFiles(String[] files) throws FileNotFoundException {
        if (files == null) {
            return null;
        }
        return new OutputStreamWriter(openStream(files));
    }

    public static Path getAppData() {
        if (appData != null) {
            return appData;
        }

        if (System.getProperty("os.name").startsWith("Windows")) {
            appData = Paths.get(System.getenv("AppData"));
        } else {
            if (System.getProperty("os.name").startsWith("Linux")) {
                String dataHome = System.getenv("XDG_DATA_HOME");
                if (dataHome != null) {
                    appData = Paths.get(dataHome);
                } else {
                    appData = Paths.get(System.getProperty("user.home"), ".local", "share");
                }
            } else {
                appData = Paths.get(System.getProperty("user.home"), ".local", "share");
            }
        }
        return appData;
    }

    public static boolean isNewer(URLConnection jarConn, Path realPath) throws IOException {
        if (realPath.toFile().isFile()) {
            long jarModified = jarConn.getLastModified();
            long realModified = Files.getLastModifiedTime(realPath).toMillis();
            return jarModified > realModified;
        }
        return true;
    }

    public static boolean writeNewer(String resourcePath, Path outPath) throws IOException {
        URL reqURL = FileUtil.class.getResource(resourcePath);
        if (reqURL == null) {
            return false;
        }
        URLConnection reqConn = reqURL.openConnection();
        if (isNewer(reqConn, outPath)) {
            Files.copy(reqConn.getInputStream(), outPath, StandardCopyOption.REPLACE_EXISTING);
        }
        reqConn.getInputStream().close();
        return true;
    }

    public static Path getLibDir() {
        return getAppData().resolve("ECTesterStandalone");
    }

    public static Path getRequirementsDir() {
        return getLibDir().resolve("lib");
    }

    public static String getLibSuffix() {
        if (System.getProperty("os.name").startsWith("Windows")) {
            return "dll";
        } else {
            return "so";
        }
    }
}
