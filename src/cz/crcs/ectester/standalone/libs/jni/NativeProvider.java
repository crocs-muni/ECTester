package cz.crcs.ectester.standalone.libs.jni;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class NativeProvider extends Provider {

    public NativeProvider(String name, double version, String info) {
        super(name, version, info);

        if (System.getSecurityManager() == null) {
            setup();
        } else {
            AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
                setup();
                return null;
            });
        }
    }

    abstract void setup();

    public static class TomCrypt extends NativeProvider {

        public TomCrypt(String name, double version, String info) {
            super(name, version, info);
        }

        @Override
        native void setup();
    }

    public static class Botan extends NativeProvider {

        public Botan(String name, double version, String info) {
            super(name, version, info);
        }

        @Override
        native void setup();
    }

    public static class Cryptopp extends NativeProvider {

        public Cryptopp(String name, double version, String info) {
            super(name, version, info);
        }

        @Override
        native void setup();
    }

    public static class Openssl extends NativeProvider {

        public Openssl(String name, double version, String info) {
            super(name, version, info);
        }

        @Override
        native void setup();
    }

    public static class Mscng extends NativeProvider {

        public Mscng(String name, double version, String info) {
            super(name, version, info);
        }

        @Override
        native void setup();
    }
}
