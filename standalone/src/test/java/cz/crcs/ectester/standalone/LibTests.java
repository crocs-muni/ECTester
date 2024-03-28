package cz.crcs.ectester.standalone;
import cz.crcs.ectester.standalone.libs.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.lang.reflect.InvocationTargetException;
import java.util.LinkedList;
import java.util.List;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class LibTests {

    ProviderECLibrary[] libs;

    @BeforeAll
    public void loadLibs() {
        List<ProviderECLibrary> libObjects = new LinkedList<>();
        Class<?>[] libClasses = new Class[]{SunECLib.class,
                BouncyCastleLib.class,
                TomcryptLib.class,
                BotanLib.class,
                CryptoppLib.class,
                OpensslLib.class,
                BoringsslLib.class,
                GcryptLib.class,
                MscngLib.class,
                WolfCryptLib.class,
                MbedTLSLib.class,
                IppcpLib.class,
                NettleLib.class,
                LibresslLib.class};
        for (Class<?> c : libClasses) {
            try {
                libObjects.add((ProviderECLibrary) c.getDeclaredConstructor().newInstance());
            } catch (NoSuchMethodException | InstantiationException | IllegalAccessException |
                     InvocationTargetException ignored) {
            }
        }
        libs = libObjects.toArray(new ProviderECLibrary[0]);
        for (ProviderECLibrary lib : libs) {
            lib.initialize();
        }
    }

    @Test
    public void loaded() {
        for (ProviderECLibrary lib : libs) {
            System.err.printf("%s: %b%n", lib.getClass().getSimpleName(), lib.isInitialized());
        }

    }
}
