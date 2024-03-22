package cz.crcs.ectester.standalone.consts;

import javax.crypto.KeyAgreement;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class KeyAgreementIdent extends Ident {
    private boolean requiresKeyAlgo;
    private String kdf;
    private String algo;

    private static final List<KeyAgreementIdent> ALL = new LinkedList<>();

    static {
        //https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
        // Basic ECDH and ECDHC (plain/raw)
        ALL.add(new KeyAgreementIdent("ECDH"));
        ALL.add(new KeyAgreementIdent("ECDHC", "ECCDH"));
        // ECDH and ECDHC with SHA as KDF, OIDs from RFC 3278
        ALL.add(new KeyAgreementIdent("ECDHwithSHA1KDF", true, "1.3.133.16.840.63.0.2"));
        ALL.add(new KeyAgreementIdent("ECCDHwithSHA1KDF", true, "1.3.133.16.840.63.0.3"));
        ALL.add(new KeyAgreementIdent("ECDHwithSHA224KDF", true, "1.3.132.1.11.0"));
        ALL.add(new KeyAgreementIdent("ECCDHwithSHA224KDF", true, "1.3.132.1.14.0"));
        ALL.add(new KeyAgreementIdent("ECDHwithSHA256KDF", true, "1.3.132.1.11.1"));
        ALL.add(new KeyAgreementIdent("ECCDHwithSHA256KDF", true, "1.3.132.1.14.1"));
        ALL.add(new KeyAgreementIdent("ECDHwithSHA384KDF", true, "1.3.132.1.11.2"));
        ALL.add(new KeyAgreementIdent("ECCDHwithSHA384KDF", true, "1.3.132.1.14.2"));
        ALL.add(new KeyAgreementIdent("ECDHwithSHA512KDF", true, "1.3.132.1.11.3"));
        ALL.add(new KeyAgreementIdent("ECCDHwithSHA512KDF", true, "1.3.132.1.14.3"));
        // Microsoft specific KDF
        ALL.add(new KeyAgreementIdent("ECDHwithSHA1KDF(CNG)"));
        ALL.add(new KeyAgreementIdent("ECDHwithSHA256KDF(CNG)"));
        ALL.add(new KeyAgreementIdent("ECDHwithSHA384KDF(CNG)"));
        ALL.add(new KeyAgreementIdent("ECDHwithSHA512KDF(CNG)"));
        // CKDF requires custom AlgorithmParameterSpec (only BouncyCastle)
        //ALL.add(new KeyAgreementIdent("ECDHwithSHA1CKDF", true));
        //ALL.add(new KeyAgreementIdent("ECCDHwithSHA1CKDF", true));
        //ALL.add(new KeyAgreementIdent("ECDHwithSHA256CKDF", true));
        //ALL.add(new KeyAgreementIdent("ECCDHwithSHA256CKDF", true));
        //ALL.add(new KeyAgreementIdent("ECDHwithSHA384CKDF", true));
        //ALL.add(new KeyAgreementIdent("ECCDHwithSHA384CKDF", true));
        //ALL.add(new KeyAgreementIdent("ECDHwithSHA512CKDF", true));
        //ALL.add(new KeyAgreementIdent("ECCDHwithSHA512CKDF", true));
        // ECMQV - Disable for now as it needs diferent params(too different from DH)
        //ALL.add(new KeyAgreementIdent("ECMQV"));
        //ALL.add(new KeyAgreementIdent("ECMQVwithSHA1KDF", true));
        //ALL.add(new KeyAgreementIdent("ECMQVwithSHA224KDF", true));
        //ALL.add(new KeyAgreementIdent("ECMQVwithSHA256KDF", true));
        //ALL.add(new KeyAgreementIdent("ECMQVwithSHA354KDF", true));
        //ALL.add(new KeyAgreementIdent("ECMQVwithSHA512KDF", true));
        //ALL.add(new KeyAgreementIdent("ECMQVwithSHA1CKDF", true, "1.3.133.16.840.63.0.16"));
        //ALL.add(new KeyAgreementIdent("ECMQVwithSHA224CKDF", true, "1.3.132.1.15.0"));
        //ALL.add(new KeyAgreementIdent("ECMQVwithSHA256CKDF", true, "1.3.132.1.15.1"));
        //ALL.add(new KeyAgreementIdent("ECMQVwithSHA384CKDF", true, "1.3.132.1.15.2"));
        //ALL.add(new KeyAgreementIdent("ECMQVwithSHA512CKDF", true, "1.3.132.1.15.3"));
        // ECVKO - Disable for now as it needs diferent params(too different from DH)
        //ALL.add(new KeyAgreementIdent("ECVKO", "ECGOST3410", "1.2.643.2.2.19", "GOST-3410-2001", "1.2.643.2.2.96"));
        //ALL.add(new KeyAgreementIdent("ECVKO256", "ECGOST3410-2012-256", "1.2.643.7.1.1.6.1", "1.2.643.7.1.1.1.1"));
        //ALL.add(new KeyAgreementIdent("ECVKO512", "ECGOST3410-2012-512", "1.2.643.7.1.1.6.2", "1.2.643.7.1.1.1.2"));
    }

    public static KeyAgreementIdent get(String ident) {
        for (KeyAgreementIdent ka : ALL) {
            if (ka.getIdents().contains(ident)) {
                return ka;
            }
        }
        return null;
    }

    public static List<KeyAgreementIdent> list() {
        return Collections.unmodifiableList(ALL);
    }

    private KeyAgreementIdent(String name, String... aliases) {
        super(name, aliases);
        if (name.contains("with")) {
            int split = name.indexOf("with");
            this.algo = name.substring(0, split);
            this.kdf = name.substring(split + 4);
        } else {
            for (String alias : aliases) {
                if (alias.contains("with")) {
                    int split = alias.indexOf("with");
                    this.algo = alias.substring(0, split);
                    this.kdf = alias.substring(split + 4);
                }
            }
        }
    }

    private KeyAgreementIdent(String name, boolean requiresKeyAlgo, String... aliases) {
        this(name, aliases);
        this.requiresKeyAlgo = requiresKeyAlgo;
    }

    public boolean requiresKeyAlgo() {
        return requiresKeyAlgo;
    }

    public String getKdfAlgo() {
        return kdf;
    }

    public String getBaseAlgo() {
        return algo;
    }

    public KeyAgreement getInstance(Provider provider) throws NoSuchAlgorithmException {
        KeyAgreement instance = getInstance((algorithm, provider1) -> {
            try {
                return KeyAgreement.getInstance(algorithm, provider1);
            } catch (NoSuchAlgorithmException e) {
                return null;
            }
        }, provider);
        instance.getProvider();
        return instance;
    }
}
