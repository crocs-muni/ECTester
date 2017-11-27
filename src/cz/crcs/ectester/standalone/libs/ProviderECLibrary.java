package cz.crcs.ectester.standalone.libs;

import cz.crcs.ectester.standalone.consts.Ident;
import cz.crcs.ectester.standalone.consts.KeyAgreementIdent;
import cz.crcs.ectester.standalone.consts.KeyPairGeneratorIdent;
import cz.crcs.ectester.standalone.consts.SignatureIdent;

import java.security.Provider;
import java.security.Security;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ProviderECLibrary implements ECLibrary {
    private Provider provider;
    private boolean initialized;

    public ProviderECLibrary(Provider provider) {
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

    private <T extends Ident> Set<T> getIdents(String type, Function<String, T> getter) {
        Set<T> results = new HashSet<>();
        if (!initialized) {
            return results;
        }

        for (Provider.Service service : provider.getServices()) {
            if (service.getType().equals(type)) {
                T id = getter.apply(service.getAlgorithm());
                if (id != null) {
                    results.add(id);
                }
            }
        }
        return results;
    }

    @Override
    public Set<KeyAgreementIdent> getECKAs() {
        return getIdents("KeyAgreement", KeyAgreementIdent::get);
    }

    @Override
    public Set<SignatureIdent> getECSigs() {
        return getIdents("Signature", SignatureIdent::get);
    }

    @Override
    public Set<KeyPairGeneratorIdent> getKPGs() {
        return getIdents("KeyPairGenerator", KeyPairGeneratorIdent::get);
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
