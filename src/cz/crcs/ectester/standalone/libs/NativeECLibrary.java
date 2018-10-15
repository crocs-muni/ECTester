package cz.crcs.ectester.standalone.libs;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.Provider;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class NativeECLibrary extends ProviderECLibrary {
    private String resource;
    private String[] requriements;

    public static String LIB_RESOURCE_DIR = "/cz/crcs/ectester/standalone/libs/jni/";

    public NativeECLibrary(String resource, String... requirements) {
        this.resource = resource;
        this.requriements = requirements;
    }

    @Override
    public boolean initialize() {
        try {
            /* Determine what OS are we running on and use appropriate suffix and path. */
            String suffix;
            Path appData;
            if (System.getProperty("os.name").startsWith("Windows")) {
                suffix = "dll";
                appData = Paths.get(System.getenv("AppData"));
            } else {
                suffix = "so";
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
            /* Resolve and create the ECTester directories in appData. */
            Path libDir = appData.resolve("ECTesterStandalone");
            File libDirFile = libDir.toFile();
            Path libReqDir = libDir.resolve("lib");
            File libReqDirFile = libReqDir.toFile();
            Path libPath = libDir.resolve(resource + "." + suffix);

            /* Create directory for shims and for requirements. */
            libDirFile.mkdirs();
            libReqDirFile.mkdirs();

            /* Write the shim. */
            writeNewer(resource + "." + suffix, libPath);

            /*
             *  Need to hack in /usr/local/lib to path.
             *  See: https://stackoverflow.com/questions/5419039/is-djava-library-path-equivalent-to-system-setpropertyjava-library-path/24988095#24988095
             */
            String path = System.getProperty("java.library.path");
            if (suffix.equals("so")) {
                String newPath = path + ":/usr/local/lib";
                System.setProperty("java.library.path", newPath);
                Field fieldSysPath;
                try {
                    fieldSysPath = ClassLoader.class.getDeclaredField("sys_paths");
                    fieldSysPath.setAccessible(true);
                    fieldSysPath.set(null, null);
                } catch (NoSuchFieldException | IllegalAccessException ignored) {
                }
            }

            /* Load the requirements, if they are bundled, write them in and load them. */
            try {
                for (String requirement : requriements) {
                    if (requirement.endsWith(suffix)) {
                        /* The requirement is bundled, write it */
                        Path reqPath = libReqDir.resolve(requirement);
                        writeNewer(requirement, reqPath);
                        System.load(reqPath.toString());
                    } else {
                        System.loadLibrary(requirement);
                    }
                }
            } catch (UnsatisfiedLinkError ule) {
                return false;
            } finally {
                if (suffix.equals("so")) {
                    System.setProperty("java.library.path", path);
                }
            }

            System.load(libPath.toString());

            provider = createProvider();
            return super.initialize();
        } catch (IOException | UnsatisfiedLinkError ex) {
            System.err.println(ex.getMessage());
        }
        return false;
    }

    private boolean isNewer(URLConnection jarConn, Path realPath) throws IOException {
        if (realPath.toFile().isFile()) {
            long jarModified = jarConn.getLastModified();
            long realModified = Files.getLastModifiedTime(realPath).toMillis();
            return jarModified > realModified;
        }
        return true;
    }

    private boolean writeNewer(String resource, Path outPath) throws IOException {
        URL reqURL = NativeECLibrary.class.getResource(LIB_RESOURCE_DIR + resource);
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

    abstract Provider createProvider();
}
