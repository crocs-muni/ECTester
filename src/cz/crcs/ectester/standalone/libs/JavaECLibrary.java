package cz.crcs.ectester.standalone.libs;

import cz.crcs.ectester.standalone.consts.KeyAgreementIdent;
import cz.crcs.ectester.standalone.consts.SignatureIdent;

import java.security.Provider;
import java.security.Security;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class JavaECLibrary implements ECLibrary {
    private Provider provider;
    private boolean initialized;

    public JavaECLibrary(Provider provider) {
        this.provider = provider;
        this.initialized = false;
    }

    @Override
    public boolean initialize() {
        try {
            int result = Security.addProvider(provider);
            if (result == -1) {
                provider = Security.getProvider(provider.getName());
            }
            initialized = true;
        } catch (NullPointerException | SecurityException ignored) {
            initialized = false;
        }
        return initialized;
    }

    @Override
    public boolean isInitialized() {
        return initialized;
    }

    @Override
    public Set<KeyAgreementIdent> getECKAs() {
        Set<KeyAgreementIdent> results = new HashSet<>();
        for (Provider.Service service : provider.getServices()) {
            if (service.getType().equals("KeyAgreement")) {
                KeyAgreementIdent id = KeyAgreementIdent.get(service.getAlgorithm());
                if (id != null) {
                    results.add(id);
                }
            }
        }
        System.out.println(results);
        return results;
    }

    @Override
    public Set<SignatureIdent> getECSigs() {
        Set<SignatureIdent> results = new HashSet<>();
        for (Provider.Service service : provider.getServices()) {
            if (service.getType().equals("Signature")) {
                SignatureIdent id = SignatureIdent.get(service.getAlgorithm());
                if (id != null) {
                    results.add(id);
                }
            }
        }
        System.out.println(results);
        return results;
    }

    @Override
    public String name() {
        return provider.getInfo();
    }

    public Provider getProvider() {
        return provider;
    }

    @Override
    public String toString() {
        return name();
    }
}
