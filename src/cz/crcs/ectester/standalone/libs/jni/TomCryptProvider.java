package cz.crcs.ectester.standalone.libs.jni;

public class TomCryptProvider extends NativeProvider {

    public TomCryptProvider(String name, double version, String info) {
        super(name, version, info);
    }

    @Override
    native void setup();
}
