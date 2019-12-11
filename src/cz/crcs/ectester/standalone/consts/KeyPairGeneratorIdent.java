package cz.crcs.ectester.standalone.consts;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class KeyPairGeneratorIdent extends Ident {
    private static final List<KeyPairGeneratorIdent> ALL = new LinkedList<>();

    static {
        ALL.add(new KeyPairGeneratorIdent("EC"));
        ALL.add(new KeyPairGeneratorIdent("ECDH"));
        ALL.add(new KeyPairGeneratorIdent("ECDSA"));
        ALL.add(new KeyPairGeneratorIdent("ECDHC"));
        ALL.add(new KeyPairGeneratorIdent("ECMQV"));
        //ALL.add(new KeyPairGeneratorIdent("ECGOST3410"));
        //ALL.add(new KeyPairGeneratorIdent("ECGOST3410-2012"));
        // ECKCDSA? Botan provides.
        ALL.add(new KeyPairGeneratorIdent("ECKCDSA"));
        // ECGDSA? Botan provides.
        ALL.add(new KeyPairGeneratorIdent("ECGDSA"));
    }

    public static KeyPairGeneratorIdent get(String ident) {
        for (KeyPairGeneratorIdent kg : ALL) {
            if (kg.getIdents().contains(ident)) {
                return kg;
            }
        }
        return null;
    }

    public static List<KeyPairGeneratorIdent> list() {
        return Collections.unmodifiableList(ALL);
    }

    public KeyPairGeneratorIdent(String name, String... aliases) {
        super(name, aliases);
    }

    public KeyPairGenerator getInstance(Provider provider) throws NoSuchAlgorithmException {
        KeyPairGenerator instance = getInstance((algorithm, provider1) -> {
            try {
                return KeyPairGenerator.getInstance(algorithm, provider1);
            } catch (NoSuchAlgorithmException e) {
                return null;
            }
        }, provider);
        instance.getProvider();
        return instance;
    }
}
