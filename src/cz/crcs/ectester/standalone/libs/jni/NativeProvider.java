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

        AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
                setup();
                return null;
            }
        });
    }

    abstract void setup();

}
