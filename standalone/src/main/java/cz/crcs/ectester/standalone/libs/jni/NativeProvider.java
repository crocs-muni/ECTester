package cz.crcs.ectester.standalone.libs.jni;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
@SuppressWarnings("serial")
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

    @SuppressWarnings("serial")
    public static class TomCrypt extends NativeProvider {

        public TomCrypt(String name, double version, String info) {
            super(name, version, info);
        }

        @Override
        native void setup();
    }

    @SuppressWarnings("serial")
    public static class Botan extends NativeProvider {

        public Botan(String name, double version, String info) {
            super(name, version, info);
        }

        @Override
        native void setup();
    }

    @SuppressWarnings("serial")
    public static class Cryptopp extends NativeProvider {

        public Cryptopp(String name, double version, String info) {
            super(name, version, info);
        }

        @Override
        native void setup();
    }

    @SuppressWarnings("serial")
    public static class Openssl extends NativeProvider {

        public Openssl(String name, double version, String info) {
            super(name, version, info);
        }

        @Override
        native void setup();
    }

    @SuppressWarnings("serial")
    public static class Boringssl extends NativeProvider {

        public Boringssl(String name, double version, String info) {
            super(name, version, info);
        }

        @Override
        native void setup();
    }

    @SuppressWarnings("serial")
    public static class Gcrypt extends NativeProvider {

        public Gcrypt(String name, double version, String info) {
            super(name, version, info);
        }

        @Override
        native void setup();
    }

    @SuppressWarnings("serial")
    public static class Mscng extends NativeProvider {

        public Mscng(String name, double version, String info) {
            super(name, version, info);
        }

        @Override
        native void setup();
    }

    @SuppressWarnings("serial")
    public static class MbedTLS extends NativeProvider {

        public MbedTLS(String name, double version, String info) {
            super(name, version, info);
        }

        @Override
        native void setup();
    }

    @SuppressWarnings("serial")
    public static class Ippcp extends NativeProvider {

        public Ippcp(String name, double version, String info) {
            super(name, version, info);
        }

        @Override
        native void setup();
    }

    @SuppressWarnings("serial")
    public static class Matrixssl extends NativeProvider {

        public Matrixssl(String name, double version, String info) {
            super(name, version, info);
        }

        @Override
        native void setup();
    }

    @SuppressWarnings("serial")
    public static class Libressl extends NativeProvider {

        public Libressl(String name, double version, String info) {
            super(name, version, info);
        }

        @Override
        native void setup();
    }

    @SuppressWarnings("serial")
    public static class Nettle extends NativeProvider {

        public Nettle(String name, double version, String info) {
            super(name, version, info);
        }

        @Override
        native void setup();
    }
}
