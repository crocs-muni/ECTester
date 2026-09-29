package cz.crcs.ectester.standalone.libs;

import java.security.KeyStore;
import java.security.Security;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.ECGenParameterSpec;

import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import java.util.Enumeration;

import org.bouncycastle.jce.ECNamedCurveTable;

/**
 * Class for representing a generic PKCS11 implementation, configured by a HW or a SW PKCS11 module.
 *
 * @author Filip Horvath
 */
public abstract class GenericPKCS11Library extends ProviderECLibrary {

    private final String PIN;

    private String providerConfigPath;

    public GenericPKCS11Library(String name) {
        this(name, null);
    }

    public GenericPKCS11Library(String name, String PIN) {
        super(name, Security.getProvider("SunPKCS11"));
        this.PIN = PIN;
    }

    public String getPIN() {
        return this.PIN;
    }

    public void setProviderConfigPath(String providerConfigPath) {
        this.providerConfigPath = providerConfigPath;
    }

    @Override
    public boolean initialize() {
        boolean initialized;
        try {
            if (this.providerConfigPath == null)
                throw new IllegalArgumentException("Provider config path must be set before initialization.");

            // configure SunPKCS11 by a config, which provides .so
            this.provider = this.provider.configure(this.providerConfigPath);
            initialized = super.initialize();
            if (!initialized || this.PIN == null) return initialized;

            // PKCS#11 login procedure
            KeyStore.getInstance("PKCS11", this.provider).load(null, this.PIN.toCharArray());
        } catch (Exception e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
            initialized = false;
        }

        return initialized;
    }

    @Override
    public Set<String> getCurves() {
        Set<String> result = new TreeSet<>();
        Enumeration<?> names = ECNamedCurveTable.getNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", this.provider);
                kpg.initialize(new ECGenParameterSpec(name));
                result.add(name);
            } catch (InvalidAlgorithmParameterException | ProviderException | NoSuchAlgorithmException e) { }
        }
        return result;
    }
}
