package cz.crcs.ectester.standalone.consts;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class SignatureIdent extends Ident {
    private String hash;
    private String sig;

    private static final List<SignatureIdent> ALL = new LinkedList<>();

    static {
        //https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
        // ECDSA
        ALL.add(new SignatureIdent("ECDSA", "SHA1withECDSA", "ECDSAwithSHA1", "1.2.840.10045.4.1", "1.3.36.3.3.2.1"));
        ALL.add(new SignatureIdent("NONEwithECDSA"));
        ALL.add(new SignatureIdent("SHA224withECDSA", "SHA224/ECDSA", "1.2.840.10045.4.3.1"));
        ALL.add(new SignatureIdent("SHA256withECDSA", "SHA256/ECDSA", "1.2.840.10045.4.3.2"));
        ALL.add(new SignatureIdent("SHA384withECDSA", "SHA384/ECDSA", "1.2.840.10045.4.3.3"));
        ALL.add(new SignatureIdent("SHA512withECDSA", "SHA512/ECDSA", "1.2.840.10045.4.3.4"));
        ALL.add(new SignatureIdent("SHA3-224withECDSA", "SHA3-224/ECDSA", "2.16.840.1.101.3.4.3.9"));
        ALL.add(new SignatureIdent("SHA3-256withECDSA", "SHA3-256/ECDSA", "2.16.840.1.101.3.4.3.10"));
        ALL.add(new SignatureIdent("SHA3-384withECDSA", "SHA3-384/ECDSA", "2.16.840.1.101.3.4.3.11"));
        ALL.add(new SignatureIdent("SHA3-512withECDSA", "SHA3-512/ECDSA", "2.16.840.1.101.3.4.3.12"));
        ALL.add(new SignatureIdent("RIPEMD160withECDSA", "RIPEMD160/ECDSA", "1.3.36.3.3.2.2"));
        // ECNR
        ALL.add(new SignatureIdent("SHA1withECNR"));
        ALL.add(new SignatureIdent("SHA224withECNR"));
        ALL.add(new SignatureIdent("SHA256withECNR"));
        ALL.add(new SignatureIdent("SHA512withECNR"));
        // CVC-ECDSA
        ALL.add(new SignatureIdent("SHA1withCVC-ECDSA", "SHA1/CVC-ECDSA", "0.4.0.127.0.7.2.2.2.2.1"));
        ALL.add(new SignatureIdent("SHA224withCVC-ECDSA", "SHA224/CVC-ECDSA", "0.4.0.127.0.7.2.2.2.2.2"));
        ALL.add(new SignatureIdent("SHA256withCVC-ECDSA", "SHA256/CVC-ECDSA", "0.4.0.127.0.7.2.2.2.2.3"));
        ALL.add(new SignatureIdent("SHA384withCVC-ECDSA", "SHA384/CVC-ECDSA", "0.4.0.127.0.7.2.2.2.2.4"));
        ALL.add(new SignatureIdent("SHA512withCVC-ECDSA", "SHA512/CVC-ECDSA", "0.4.0.127.0.7.2.2.2.2.5"));
        // PLAIN-ECDSA
        ALL.add(new SignatureIdent("SHA1withPLAIN-ECDSA", "SHA1/PLAIN-ECDSA", "0.4.0.127.0.7.1.1.4.1.1"));
        ALL.add(new SignatureIdent("SHA224withPLAIN-ECDSA", "SHA224/PLAIN-ECDSA", "0.4.0.127.0.7.1.1.4.1.2"));
        ALL.add(new SignatureIdent("SHA256withPLAIN-ECDSA", "SHA256/PLAIN-ECDSA", "0.4.0.127.0.7.1.1.4.1.3"));
        ALL.add(new SignatureIdent("SHA384withPLAIN-ECDSA", "SHA384/PLAIN-ECDSA", "0.4.0.127.0.7.1.1.4.1.4"));
        ALL.add(new SignatureIdent("SHA512withPLAIN-ECDSA", "SHA512/PLAIN-ECDSA", "0.4.0.127.0.7.1.1.4.1.5"));
        ALL.add(new SignatureIdent("RIPEMD160withPLAIN-ECDSA", "RIPEMD160/PLAIN-ECDSA", "0.4.0.127.0.7.1.1.4.1.6"));
        // ECGOST
        ALL.add(new SignatureIdent("ECGOST3410", "ECGOST-3410", "GOST-3410-2001"));
        ALL.add(new SignatureIdent("GOST3411withECGOST3410", "GOST3411/ECGOST3410", "1.2.643.2.2.3"));
        ALL.add(new SignatureIdent("ECGOST3410-2012-256", "GOST-3410-2012-256"));
        ALL.add(new SignatureIdent("GOST3411-2012-256withECGOST3410-2012-256", "GOST3411-2012-256/ECGOST3410-2012-2560", "1.2.643.7.1.1.3.2"));
        ALL.add(new SignatureIdent("ECGOST3410-2012-512", "GOST-3410-2012-512"));
        ALL.add(new SignatureIdent("GOST3411-2012-512withECGOST3410-2012-512", "GOST3411-2012-512/ECGOST3410-2012-5120", "1.2.643.7.1.1.3.3"));
        ALL.add(new SignatureIdent("SM3withSM2"));
        // ECDDSA (rfc6979?)
        ALL.add(new SignatureIdent("ECDDSA", "SHA1withECDDSA", "SHA1withDETECDSA", "DETECDSA", "ECDETDSA"));
        ALL.add(new SignatureIdent("SHA224withECDDSA", "SHA224withDETECDSA"));
        ALL.add(new SignatureIdent("SHA256withECDDSA", "SHA256withDETECDSA"));
        ALL.add(new SignatureIdent("SHA384withECDDSA", "SHA384withDETECDSA"));
        ALL.add(new SignatureIdent("SHA512withECDDSA", "SHA512withDETECDSA"));
        ALL.add(new SignatureIdent("SHA3-224withECDDSA", "SHA3-224withDETECDSA"));
        ALL.add(new SignatureIdent("SHA3-256withECDDSA", "SHA3-256withDETECDSA"));
        ALL.add(new SignatureIdent("SHA3-384withECDDSA", "SHA3-384withDETECDSA"));
        ALL.add(new SignatureIdent("SHA3-512withECDDSA", "SHA3-512withDETECDSA"));
        // ECKCDSA? Botan provides.
        ALL.add(new SignatureIdent("ECKCDSA", "SHA1withECKCDSA", "1.2.410.200004.1.100.4.3"));
        ALL.add(new SignatureIdent("NONEwithECKCDSA"));
        ALL.add(new SignatureIdent("RIPEMD160withECKCDSA"));
        ALL.add(new SignatureIdent("SHA224withECKCDSA", "1.2.410.200004.1.100.4.4"));
        ALL.add(new SignatureIdent("SHA256withECKCDSA", "1.2.410.200004.1.100.4.5"));
        ALL.add(new SignatureIdent("SHA384withECKCDSA"));
        ALL.add(new SignatureIdent("SHA512withECKCDSA"));
        // ECGDSA? Botan provides.
        ALL.add(new SignatureIdent("ECGDSA", "SHA1withECGDSA", "1.3.36.3.3.2.5.4.2"));
        ALL.add(new SignatureIdent("NONEwithECGDSA"));
        ALL.add(new SignatureIdent("RIPEMD160withECGDSA", "1.3.36.3.3.2.5.4.1"));
        ALL.add(new SignatureIdent("SHA224withECGDSA", "1.3.36.3.3.2.5.4.3"));
        ALL.add(new SignatureIdent("SHA224withECGDSA", "1.3.36.3.3.2.5.4.4"));
        ALL.add(new SignatureIdent("SHA384withECGDSA", "1.3.36.3.3.2.5.4.5"));
        ALL.add(new SignatureIdent("SHA512withECGDSA", "1.3.36.3.3.2.5.4.6"));
    }

    public static SignatureIdent get(String ident) {
        for (SignatureIdent sig : ALL) {
            if (sig.getIdents().contains(ident)) {
                return sig;
            }
        }
        return null;
    }

    public static List<SignatureIdent> list() {
        return Collections.unmodifiableList(ALL);
    }

    private SignatureIdent(String name, String... aliases) {
        super(name, aliases);
        if (name.contains("with")) {
            int split = name.indexOf("with");
            this.hash = name.substring(0, split);
            this.sig = name.substring(split + 4);
        } else {
            for (String alias : aliases) {
                if (alias.contains("with")) {
                    int split = alias.indexOf("with");
                    this.hash = alias.substring(0, split);
                    this.sig = alias.substring(split + 4);
                    break;
                }
            }
        }
    }

    public Signature getInstance(Provider provider) throws NoSuchAlgorithmException {
        Signature instance = getInstance((algorithm, provider1) -> {
            try {
                return Signature.getInstance(algorithm, provider1);
            } catch (NoSuchAlgorithmException e) {
                return null;
            }
        }, provider);
        instance.getProvider();
        return instance;
    }

    public String getHashAlgo() {
        return hash;
    }

    public String getSigType() {
        return sig;
    }
}
