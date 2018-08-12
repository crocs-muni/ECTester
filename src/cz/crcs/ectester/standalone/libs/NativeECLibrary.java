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
            Path libDir = appData.resolve("ECTesterStandalone");
            File libDirFile = libDir.toFile();
            Path libPath = libDir.resolve(resource + "." + suffix);
            File libFile = libPath.toFile();

            URL jarURL = NativeECLibrary.class.getResource(LIB_RESOURCE_DIR + resource + "." + suffix);
            if (jarURL == null) {
                return false;
            }
            URLConnection jarConnection = jarURL.openConnection();

            /* Only write the file if it does not exist,
             * or if the existing one is older than the
             * one in the JAR.
             */
            boolean write = false;
            if (libDirFile.isDirectory() && libFile.isFile()) {
                long jarModified = jarConnection.getLastModified();

                long libModified = Files.getLastModifiedTime(libPath).toMillis();
                if (jarModified > libModified) {
                    write = true;
                }
            } else {
                libDir.toFile().mkdirs();
                libFile.createNewFile();
                write = true;
            }

            if (write) {
                Files.copy(jarConnection.getInputStream(), libPath, StandardCopyOption.REPLACE_EXISTING);
            }
            jarConnection.getInputStream().close();

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

            for (String requirement : requriements) {
                System.loadLibrary(requirement);
            }

            if (suffix.equals("so")) {
                System.setProperty("java.library.path", path);
            }

            System.load(libPath.toString());

            provider = createProvider();
            return super.initialize();
        } catch (IOException | UnsatisfiedLinkError ex) {
            System.err.println(ex.getMessage());
        }
        return false;
    }

    abstract Provider createProvider();
}
