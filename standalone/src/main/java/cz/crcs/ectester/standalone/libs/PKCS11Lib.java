package cz.crcs.ectester.standalone.libs;

import java.util.Arrays;

public class PKCS11Lib extends GenericPKCS11Library {

    public PKCS11Lib() {
        this("",
                System.getenv("PKCS11_CFG"),
                System.getenv("PIN"));
    }

    public PKCS11Lib(String name, String providerConfigPath, String pin) {
        super(name, pin);
        this.setProviderConfigPath(providerConfigPath);
    }

    @Override
    public String name() {
        if (super.name() != null) {
            return super.name();
        }

        // we assume provider name will be SunPKCS11-<nameFromConfig>
        String[] names = this.provider.getName().split("-");
        return Arrays.stream(names)
                .filter(name -> !name.equals("SunPKCS11"))
                .reduce("", (s, s2) -> s + "-" + s2);
    }
}
