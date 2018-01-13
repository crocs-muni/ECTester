package cz.crcs.ectester.standalone.consts;

import javax.crypto.KeyAgreement;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class KeyAgreementIdent extends Ident {
    private static final List<KeyAgreementIdent> ALL = new LinkedList<>();

    static {
        //https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
        // Basic ECDH and ECDHC (plain/raw)
        ALL.add(new KeyAgreementIdent("ECDH"));
        ALL.add(new KeyAgreementIdent("ECDHC", "ECCDH"));
        // ECDH and ECDHC with SHA as KDF, OIDs from RFC 3278
        ALL.add(new KeyAgreementIdent("ECDHwithSHA1KDF", "1.3.133.16.840.63.0.2"));
        ALL.add(new KeyAgreementIdent("ECCDHwithSHA1KDF", "1.3.133.16.840.63.0.3"));
        ALL.add(new KeyAgreementIdent("ECDHwithSHA224KDF", "1.3.132.1.11.0"));
        ALL.add(new KeyAgreementIdent("ECCDHwithSHA224KDF", "1.3.132.1.14.0"));
        ALL.add(new KeyAgreementIdent("ECDHwithSHA256KDF", "1.3.132.1.11.1"));
        ALL.add(new KeyAgreementIdent("ECCDHwithSHA256KDF", "1.3.132.1.14.1"));
        ALL.add(new KeyAgreementIdent("ECDHwithSHA384KDF", "1.3.132.1.11.2"));
        ALL.add(new KeyAgreementIdent("ECCDHwithSHA384KDF", "1.3.132.1.14.2"));
        ALL.add(new KeyAgreementIdent("ECDHwithSHA512KDF", "1.3.132.1.11.3"));
        ALL.add(new KeyAgreementIdent("ECCDHwithSHA512KDF", "1.3.132.1.14.3"));
        // ECMQV - Disable for now as it needs diferent params(too different from DH)
        //ALL.add(new KeyAgreementIdent("ECMQV"));
        //ALL.add(new KeyAgreementIdent("ECMQVwithSHA1CKDF", "1.3.133.16.840.63.0.16"));
        //ALL.add(new KeyAgreementIdent("ECMQVwithSHA224CKDF", "1.3.132.1.15.0"));
        //ALL.add(new KeyAgreementIdent("ECMQVwithSHA256CKDF", "1.3.132.1.15.1"));
        //ALL.add(new KeyAgreementIdent("ECMQVwithSHA384CKDF", "1.3.132.1.15.2"));
        //ALL.add(new KeyAgreementIdent("ECMQVwithSHA512CKDF", "1.3.132.1.15.3"));
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

    private KeyAgreementIdent(String name, String... aliases) {
        super(name, aliases);
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
