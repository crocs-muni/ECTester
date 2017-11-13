package cz.crcs.ectester.standalone.consts;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
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
    }

    public static KeyPairGeneratorIdent get(String ident) {
        for (KeyPairGeneratorIdent kg : ALL) {
            if (kg.getIdents().contains(ident)) {
                return kg;
            }
        }
        return null;
    }

    public KeyPairGeneratorIdent(String name, String... aliases) {
        super(name, aliases);
    }

    public KeyPairGenerator getInstance(Provider provider) throws NoSuchAlgorithmException {
        return KeyPairGenerator.getInstance(name, provider);
    }
}
