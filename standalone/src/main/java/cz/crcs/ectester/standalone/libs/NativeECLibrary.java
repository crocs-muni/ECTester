package cz.crcs.ectester.standalone.libs;

import cz.crcs.ectester.common.util.FileUtil;
import cz.crcs.ectester.standalone.ECTesterStandalone;

import java.io.IOException;
import java.nio.file.Path;
import java.security.Provider;
import java.util.Set;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class NativeECLibrary extends ProviderECLibrary {
    private final String resource;
    private final String[] requriements;


    public NativeECLibrary(String resource, String... requirements) {
        this.resource = resource;
        this.requriements = requirements;
    }

    @Override
    public boolean initialize() {
        try {
            /* Determine what OS are we running on and use appropriate suffix and path. */
            String suffix = FileUtil.getLibSuffix();

            /* Resolve and create the ECTester directories in appData. */
            Path libDir = FileUtil.getLibDir();
            Path libReqDir = FileUtil.getRequirementsDir();
            Path libPath = libDir.resolve(resource + "." + suffix);

            /* Write the shim. */
            boolean found = FileUtil.writeNewer(ECTesterStandalone.LIB_RESOURCE_DIR + resource + "." + suffix, libPath);
            if (!found) {
                return false;
            }

            /* Load the requirements, if they are bundled, write them in and load them. */
            try {
                for (String requirement : requriements) {
                    if (requirement.endsWith(suffix)) {
                        /* The requirement is bundled, write it */
                        Path reqPath = libReqDir.resolve(requirement);
                        found = FileUtil.writeNewer(ECTesterStandalone.LIB_RESOURCE_DIR + requirement, reqPath);
                        if (!found) {
                            return false;
                        }
                        System.load(reqPath.toString());
                    } else {
                        System.loadLibrary(requirement);
                    }
                }
            } catch (UnsatisfiedLinkError ule) {
                System.err.println(resource);
                ule.printStackTrace();
                return false;
            }

            System.load(libPath.toString());

            provider = createProvider();
            return super.initialize();
        } catch (IOException | UnsatisfiedLinkError ignored) {
            System.err.println(resource);
            ignored.printStackTrace();
        }
        return false;
    }


    @Override
    public native Set<String> getNativeTimingSupport();

    @Override
    public native boolean setNativeTimingType(String type);

    @Override
    public native long getNativeTimingResolution();

    @Override
    public native String getNativeTimingUnit();

    @Override
    public native long getLastNativeTiming();

    abstract Provider createProvider();
}
