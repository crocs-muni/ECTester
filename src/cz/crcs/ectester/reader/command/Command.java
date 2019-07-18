package cz.crcs.ectester.reader.command;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.ec.EC_Params;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.common.util.CardUtil;
import cz.crcs.ectester.common.util.ECUtil;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.output.ResponseWriter;
import cz.crcs.ectester.reader.response.Response;
import javacard.security.KeyPair;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class Command implements Cloneable {
    CommandAPDU cmd;
    CardMngr cardManager;
    // Workaround for a stupid Java bug that went unfixed for !12! years,
    // and for the even more stupid module system, which cannot properly work
    // with the fact that JCardSim has some java.* packages...
    final byte[] GOD_DAMN_JAVA_BUG_6474858_AND_GOD_DAMN_JAVA_12_MODULE_SYSTEM = new byte[]{0};


    Command(CardMngr cardManager) {
        this.cardManager = cardManager;
    }

    public CommandAPDU getAPDU() {
        return cmd;
    }

    public abstract Response send() throws CardException;

    public static List<Response> sendAll(List<Command> commands) throws CardException {
        List<Response> result = new ArrayList<>();
        for (Command cmd : commands) {
            result.add(cmd.send());
        }
        return result;
    }

    public abstract String getDescription();

    @Override
    protected Command clone() throws CloneNotSupportedException {
        return (Command) super.clone();
    }

    public static EC_Curve findCurve(ECTesterReader.Config cfg, short keyLength, byte keyClass) throws IOException {
        if (cfg.customCurve) {
            byte curveId = EC_Consts.getCurve(keyLength, keyClass);
            return EC_Store.getInstance().getObject(EC_Curve.class, "secg", CardUtil.getCurveName(curveId));
        } else if (cfg.namedCurve != null) {
            EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, cfg.namedCurve);
            if (curve == null) {
                throw new IOException("Curve could no be found.");
            }
            if (curve.getBits() != keyLength) {
                throw new IOException("Curve bits mismatch: " + curve.getBits() + " vs " + keyLength + " entered.");
            }
            if (curve.getField() != keyClass) {
                throw new IOException("Curve field mismatch.");
            }
            return curve;
        } else if (cfg.curveFile != null) {
            EC_Curve curve = new EC_Curve(null, keyLength, keyClass);

            FileInputStream in = new FileInputStream(cfg.curveFile);
            curve.readCSV(in);
            in.close();
            return curve;
        } else {
            return null;
        }
    }


    /**
     * @param keyPair   which keyPair/s (local/remote) to set curve domain parameters on
     * @param keyLength key length to choose
     * @param keyClass  key class to choose
     * @return a Command to send in order to prepare the curve on the keypairs.
     * @throws IOException if curve file cannot be found/opened
     */
    public static Command prepareCurve(CardMngr cardManager, ECTesterReader.Config cfg, byte keyPair, short keyLength, byte keyClass) throws IOException {
        if (cfg.customCurve) {
            // Set custom curve (one of the SECG curves embedded applet-side)
            short domainParams = keyClass == KeyPair.ALG_EC_FP ? EC_Consts.PARAMETERS_DOMAIN_FP : EC_Consts.PARAMETERS_DOMAIN_F2M;
            return new Command.Set(cardManager, keyPair, EC_Consts.getCurve(keyLength, keyClass), domainParams, null);
        }

        EC_Curve curve = findCurve(cfg, keyLength, keyClass);
        if ((curve == null || curve.flatten() == null) && (cfg.namedCurve != null || cfg.curveFile != null)) {
            if (cfg.namedCurve != null) {
                throw new IOException("Couldn't read named curve data.");
            }
            throw new IOException("Couldn't read the curve file correctly.");
        } else if (curve == null) {
            return null;
        }
        return new Command.Set(cardManager, keyPair, EC_Consts.CURVE_external, curve.getParams(), curve.flatten());
    }


    /**
     * @param cardManager
     * @param dataStore
     * @param cfg
     * @param keyPair       which keyPair/s to set the key params on
     * @param allowedParams
     * @return a CommandAPDU setting params loaded on the keyPair/s
     * @throws IOException if any of the key files cannot be found/opened
     */
    public static Command prepareKey(CardMngr cardManager, EC_Store dataStore, ECTesterReader.Config cfg, byte keyPair, short allowedParams) throws IOException {
        short params = EC_Consts.PARAMETERS_NONE;
        byte[] data = null;

        if (cfg.key != null || cfg.namedKey != null) {
            params |= EC_Consts.PARAMETERS_KEYPAIR;
            EC_Params keypair = ECUtil.loadParams(EC_Consts.PARAMETERS_KEYPAIR, cfg.namedKey, cfg.key);
            if (keypair == null) {
                throw new IOException("KeyPair not found.");
            }

            data = keypair.flatten();
            if (data == null) {
                throw new IOException("Couldn't read the key file correctly.");
            }
        }

        if ((cfg.publicKey != null || cfg.namedPublicKey != null) && ((allowedParams & EC_Consts.PARAMETER_W) != 0)) {
            params |= EC_Consts.PARAMETER_W;
            EC_Params pub = ECUtil.loadParams(EC_Consts.PARAMETER_W, cfg.namedPublicKey, cfg.publicKey);
            if (pub == null) {
                throw new IOException("Public key not found.");
            }

            byte[] pubkey = pub.flatten(EC_Consts.PARAMETER_W);
            if (pubkey == null) {
                throw new IOException("Couldn't read the public key file correctly.");
            }
            data = pubkey;
        }

        if ((cfg.privateKey != null || cfg.namedPrivateKey != null) && ((allowedParams & EC_Consts.PARAMETER_S) != 0)) {
            params |= EC_Consts.PARAMETER_S;
            EC_Params priv = ECUtil.loadParams(EC_Consts.PARAMETER_S, cfg.namedPrivateKey, cfg.privateKey);
            if (priv == null) {
                throw new IOException("Private key not found.");
            }

            byte[] privkey = priv.flatten(EC_Consts.PARAMETER_S);
            if (privkey == null) {
                throw new IOException("Couldn't read the private key file correctly.");
            }
            data = ByteUtil.concatenate(data, privkey);
        }
        return new Command.Set(cardManager, keyPair, EC_Consts.CURVE_external, params, data);
    }

    public static long dryRunTime(CardMngr cardManager, Command cmd, int num, ResponseWriter respWriter) throws CardException {
        long time = 0;
        respWriter.outputResponse(new Command.SetDryRunMode(cardManager, ECTesterApplet.MODE_DRY_RUN).send());
        for (int i = 0; i < num; ++i) {
            Response dry = cmd.send();
            respWriter.outputResponse(dry);
            time += dry.getDuration();
        }
        time /= num;
        respWriter.outputResponse(new Command.SetDryRunMode(cardManager, ECTesterApplet.MODE_NORMAL).send());
        return time;
    }

    /**
     *
     */
    public static class AllocateKeyAgreement extends Command {
        private byte kaType;

        /**
         * Creates the INS_ALLOCATE_KA instruction.
         *
         * @param cardManager cardManager to send APDU through
         * @param kaType      which type of KeyAgreement to use
         */
        public AllocateKeyAgreement(CardMngr cardManager, byte kaType) {
            super(cardManager);
            this.kaType = kaType;
            byte[] data = new byte[]{kaType};
            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_ALLOCATE_KA, 0x00, 0x00, data);
        }

        @Override
        public Response.AllocateKeyAgreement send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.AllocateKeyAgreement(response, getDescription(), elapsed, kaType);
        }

        @Override
        public String getDescription() {
            return String.format("Allocate KeyAgreement(%s) object", CardUtil.getKATypeString(kaType));
        }
    }

    /**
     *
     */
    public static class AllocateSignature extends Command {
        private byte sigType;

        /**
         * Creates the INS_ALLOCATE_SIG instruction.
         *
         * @param cardManager cardManager to send APDU through
         * @param sigType     which type of Signature to use
         */
        public AllocateSignature(CardMngr cardManager, byte sigType) {
            super(cardManager);
            this.sigType = sigType;
            byte[] data = new byte[]{sigType};
            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_ALLOCATE_SIG, 0x00, 0x00, data);
        }

        @Override
        public Response.AllocateSignature send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.AllocateSignature(response, getDescription(), elapsed, sigType);
        }

        @Override
        public String getDescription() {
            return String.format("Allocate Signature(%s) object", CardUtil.getSigTypeString(sigType));
        }
    }

    /**
     *
     */
    public static class Allocate extends Command {
        private byte keyPair;
        private byte build;
        private short keyLength;
        private byte keyClass;

        /**
         * Creates the INS_ALLOCATE instruction.
         *
         * @param cardManager cardManager to send APDU through
         * @param keyPair     which keyPair to use, local/remote (KEYPAIR_* | ...)
         * @param build       whether to use KeyBuilder or Keypair alloc
         * @param keyLength   key length to set
         * @param keyClass    key class to allocate
         */
        public Allocate(CardMngr cardManager, byte keyPair, byte build, short keyLength, byte keyClass) {
            super(cardManager);
            this.keyPair = keyPair;
            this.build = build;
            this.keyLength = keyLength;
            this.keyClass = keyClass;

            byte[] data = new byte[]{0, 0, keyClass};
            ByteUtil.setShort(data, 0, keyLength);
            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_ALLOCATE, keyPair, build, data);
        }

        public Allocate(CardMngr cardManager, byte keyPair, short keyLength, byte keyClass) {
            this(cardManager, keyPair, (byte) (ECTesterApplet.BUILD_KEYPAIR | ECTesterApplet.BUILD_KEYBUILDER), keyLength, keyClass);
        }

        @Override
        public Response.Allocate send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.Allocate(response, getDescription(), elapsed, keyPair, keyLength, keyClass);
        }

        @Override
        public String getDescription() {
            String field = keyClass == KeyPair.ALG_EC_FP ? "ALG_EC_FP" : "ALG_EC_F2M";
            String key;
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                key = "both keypairs";
            } else {
                key = ((keyPair == ECTesterApplet.KEYPAIR_LOCAL) ? "local" : "remote") + " keypair";
            }
            return String.format("Allocate %s %db %s", key, keyLength, field);
        }
    }

    /**
     *
     */
    public static class Clear extends Command {
        private byte keyPair;

        /**
         * @param cardManager cardManager to send APDU through
         * @param keyPair     which keyPair clear, local/remote (KEYPAIR_* || ...)
         */
        public Clear(CardMngr cardManager, byte keyPair) {
            super(cardManager);
            this.keyPair = keyPair;

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_CLEAR, keyPair, 0x00, GOD_DAMN_JAVA_BUG_6474858_AND_GOD_DAMN_JAVA_12_MODULE_SYSTEM);
        }

        @Override
        public Response.Clear send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.Clear(response, getDescription(), elapsed, keyPair);
        }

        @Override
        public String getDescription() {
            String key;
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                key = "both keypairs";
            } else {
                key = ((keyPair == ECTesterApplet.KEYPAIR_LOCAL) ? "local" : "remote") + " keypair";
            }
            return String.format("Clear %s", key);
        }
    }

    /**
     *
     */
    public static class Set extends Command {
        private byte keyPair;
        private byte curve;
        private short params;
        private byte[] external;

        /**
         * Creates the INS_SET instruction.
         *
         * @param cardManager cardManager to send APDU through
         * @param keyPair     which keyPair to set params on, local/remote (KEYPAIR_* || ...)
         * @param curve       curve to set (EC_Consts.CURVE_*)
         * @param params      parameters to set (EC_Consts.PARAMETER_* | ...)
         * @param external    external curve data, can be null
         */
        public Set(CardMngr cardManager, byte keyPair, byte curve, short params, byte[] external) {
            super(cardManager);
            this.keyPair = keyPair;
            this.curve = curve;
            this.params = params;
            this.external = external;

            int len = external != null ? 2 + external.length : 2;
            byte[] data = new byte[len];
            ByteUtil.setShort(data, 0, params);
            if (external != null) {
                System.arraycopy(external, 0, data, 2, external.length);
            }

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_SET, keyPair, curve, data);
        }

        @Override
        public Response.Set send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.Set(response, getDescription(), elapsed, keyPair, curve, params);
        }

        @Override
        public String getDescription() {
            String name = CardUtil.getCurveName(curve);
            String what = CardUtil.getParameterString(params);

            String pair;
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                pair = "both keypairs";
            } else {
                pair = ((keyPair == ECTesterApplet.KEYPAIR_LOCAL) ? "local" : "remote") + " keypair";
            }
            return String.format("Set %s %s parameters on %s", name, what, pair);
        }
    }

    /**
     *
     */
    public static class Transform extends Command {
        private byte keyPair;
        private byte key;
        private short params;
        private short transformation;

        /**
         * @param cardManager    cardManager to send APDU through
         * @param keyPair        which keyPair to transform, local/remote (KEYPAIR_* || ...)
         * @param key            key to transform (EC_Consts.KEY_* | ...)
         * @param params         parameters to transform (EC_Consts.PARAMETER_* | ...)
         * @param transformation transformation type (EC_Consts.TRANSFORMATION_*)
         */
        public Transform(CardMngr cardManager, byte keyPair, byte key, short params, short transformation) {
            super(cardManager);
            this.keyPair = keyPair;
            this.key = key;
            this.params = params;
            this.transformation = transformation;

            byte[] data = new byte[4];
            ByteUtil.setShort(data, 0, params);
            ByteUtil.setShort(data, 2, transformation);

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_TRANSFORM, keyPair, key, data);
        }

        @Override
        public Response.Transform send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.Transform(response, getDescription(), elapsed, keyPair, key, params, transformation);
        }

        @Override
        public String getDescription() {
            String stringParams = CardUtil.getParams(params);
            String transform = CardUtil.getTransformation(transformation);

            String pair;
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                pair = "both keypairs";
            } else {
                pair = ((keyPair == ECTesterApplet.KEYPAIR_LOCAL) ? "local" : "remote") + " keypair";
            }
            return String.format("Transform params %s of %s, %s", stringParams, pair, transform);
        }
    }

    /**
     *
     */
    public static class Generate extends Command {
        private byte keyPair;

        /**
         * Creates the INS_GENERATE instruction.
         *
         * @param cardManager cardManager to send APDU through
         * @param keyPair     which keyPair to generate, local/remote (KEYPAIR_* || ...)
         */
        public Generate(CardMngr cardManager, byte keyPair) {
            super(cardManager);
            this.keyPair = keyPair;

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_GENERATE, keyPair, 0, GOD_DAMN_JAVA_BUG_6474858_AND_GOD_DAMN_JAVA_12_MODULE_SYSTEM);
        }

        @Override
        public Response.Generate send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.Generate(response, getDescription(), elapsed, keyPair);
        }

        @Override
        public String getDescription() {
            String key;
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                key = "both keypairs";
            } else {
                key = ((keyPair == ECTesterApplet.KEYPAIR_LOCAL) ? "local" : "remote") + " keypair";
            }
            return String.format("Generate %s", key);
        }
    }

    /**
     *
     */
    public static class Export extends Command {
        private byte keyPair;
        private byte key;
        private short params;

        /**
         * Creates the INS_EXPORT instruction.
         *
         * @param cardManager cardManager to send APDU through
         * @param keyPair     keyPair to export from (KEYPAIR_* | ...)
         * @param key         key to export from (EC_Consts.KEY_* | ...)
         * @param params      params to export (EC_Consts.PARAMETER_* | ...)
         */
        public Export(CardMngr cardManager, byte keyPair, byte key, short params) {
            super(cardManager);
            this.keyPair = keyPair;
            this.key = key;
            this.params = params;

            byte[] data = new byte[2];
            ByteUtil.setShort(data, 0, params);

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_EXPORT, keyPair, key, data);
        }

        @Override
        public Response.Export send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.Export(response, getDescription(), elapsed, keyPair, key, params);
        }

        @Override
        public String getDescription() {
            String what = CardUtil.getParameterString(params);

            String source;
            if (key == EC_Consts.KEY_BOTH) {
                source = "both keys";
            } else {
                source = ((key == EC_Consts.KEY_PUBLIC) ? "public" : "private") + " key";
            }
            String pair;
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                pair = "both keypairs";
            } else {
                pair = ((keyPair == ECTesterApplet.KEYPAIR_LOCAL) ? "local" : "remote") + " keypair";
            }
            return String.format("Export %s params from %s of %s", what, source, pair);
        }
    }

    /**
     *
     */
    public static class ECDH extends Command {
        private byte pubkey;
        private byte privkey;
        private byte export;
        private short transformation;
        private byte type;

        /**
         * Creates the INS_ECDH instruction.
         *
         * @param cardManager    cardManager to send APDU through
         * @param pubkey         keyPair to use for public key, (KEYPAIR_LOCAL || KEYPAIR_REMOTE)
         * @param privkey        keyPair to use for private key, (KEYPAIR_LOCAL || KEYPAIR_REMOTE)
         * @param export         whether to export ECDH secret
         * @param transformation whether to transform the pubkey before ECDH (EC_Consts.TRANSFORMATION_* | ...)
         * @param type           ECDH algorithm type (EC_Consts.KA_* | ...)
         */
        public ECDH(CardMngr cardManager, byte pubkey, byte privkey, byte export, short transformation, byte type) {
            super(cardManager);
            this.pubkey = pubkey;
            this.privkey = privkey;
            this.export = export;
            this.transformation = transformation;
            this.type = type;

            byte[] data = new byte[]{export, 0, 0, type};
            ByteUtil.setShort(data, 1, transformation);

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_ECDH, pubkey, privkey, data);
        }

        @Override
        public Response.ECDH send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.ECDH(response, getDescription(), elapsed, pubkey, privkey, export, transformation, type);
        }

        @Override
        public String getDescription() {
            String algo = CardUtil.getKATypeString(type);

            String pub = pubkey == ECTesterApplet.KEYPAIR_LOCAL ? "local" : "remote";
            String priv = privkey == ECTesterApplet.KEYPAIR_LOCAL ? "local" : "remote";

            String validity;
            if (transformation == EC_Consts.TRANSFORMATION_NONE) {
                validity = "";
            } else {
                validity = String.format("(%s point)", CardUtil.getTransformation(transformation));
            }
            return String.format("%s of %s pubkey and %s privkey%s", algo, pub, priv, validity);
        }
    }

    /**
     *
     */
    public static class ECDH_direct extends Command {
        private byte privkey;
        private byte export;
        private short transformation;
        private byte type;
        private byte[] pubkey;

        /**
         * Creates the INS_ECDH_DIRECT instruction.
         *
         * @param cardManager    cardManager to send APDU through
         * @param privkey        keyPair to use for private key, (KEYPAIR_LOCAL || KEYPAIR_REMOTE)
         * @param export         whether to export ECDH secret
         * @param transformation whether to transform the pubkey before ECDH (EC_Consts.TRANSFORMATION_* | ...)
         * @param type           EC KeyAgreement type
         * @param pubkey         pubkey data to do ECDH with.
         */
        public ECDH_direct(CardMngr cardManager, byte privkey, byte export, short transformation, byte type, byte[] pubkey) {
            super(cardManager);
            this.privkey = privkey;
            this.export = export;
            this.transformation = transformation;
            this.type = type;
            this.pubkey = pubkey;

            byte[] data = new byte[3 + pubkey.length];
            ByteUtil.setShort(data, 0, transformation);
            data[2] = type;
            System.arraycopy(pubkey, 0, data, 3, pubkey.length);

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_ECDH_DIRECT, privkey, export, data);
        }

        @Override
        public Response.ECDH send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.ECDH(response, getDescription(), elapsed, ECTesterApplet.KEYPAIR_REMOTE, privkey, export, transformation, type);
        }

        @Override
        public String getDescription() {
            String algo = CardUtil.getKATypeString(type);

            String priv = privkey == ECTesterApplet.KEYPAIR_LOCAL ? "local" : "remote";

            String validity;
            if (transformation == EC_Consts.TRANSFORMATION_NONE) {
                validity = "";
            } else {
                validity = String.format("(%s point)", CardUtil.getTransformation(transformation));
            }
            return String.format("%s of external pubkey and %s privkey%s", algo, priv, validity);
        }
    }

    public static class ECDSA extends Command {
        private byte keyPair;
        private byte sigType;
        private byte export;
        private byte[] raw;

        /**
         * Creates the INS_ECDSA instruction.
         *
         * @param cardManager cardManager to send APDU through
         * @param keyPair     keyPair to use for signing and verification (KEYPAIR_LOCAL || KEYPAIR_REMOTE)
         * @param sigType     Signature type to use
         * @param export      whether to export ECDSA signature
         * @param raw         data to sign, can be null, in which case random data is signed.
         */
        public ECDSA(CardMngr cardManager, byte keyPair, byte sigType, byte export, byte[] raw) {
            super(cardManager);
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                throw new IllegalArgumentException();
            }

            this.keyPair = keyPair;
            this.sigType = sigType;
            this.export = export;
            this.raw = raw;

            int len = raw != null ? raw.length : 0;
            byte[] data = new byte[3 + len];
            data[0] = sigType;
            ByteUtil.setShort(data, 1, (short) len);
            if (raw != null) {
                System.arraycopy(raw, 0, data, 3, len);
            }

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_ECDSA, keyPair, export, data);
        }

        @Override
        public Response.ECDSA send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.ECDSA(response, getDescription(), elapsed, keyPair, sigType, export, raw);
        }

        @Override
        public String getDescription() {
            String algo = CardUtil.getSigTypeString(sigType);
            String key = keyPair == ECTesterApplet.KEYPAIR_LOCAL ? "local" : "remote";
            String data = raw == null ? "random" : "provided";
            return String.format("%s with %s keypair(%s data)", algo, key, data);
        }
    }

    public static class ECDSA_sign extends Command {
        private byte keyPair;
        private byte sigType;
        private byte export;
        private byte[] raw;

        /**
         * Creates the INS_ECDSA_SIGN instruction.
         *
         * @param cardManager cardManager to send APDU through
         * @param keyPair     keyPair to use for signing and verification (KEYPAIR_LOCAL || KEYPAIR_REMOTE)
         * @param sigType     Signature type to use
         * @param export      whether to export ECDSA signature
         * @param raw         data to sign, can be null, in which case random data is signed.
         */
        public ECDSA_sign(CardMngr cardManager, byte keyPair, byte sigType, byte export, byte[] raw) {
            super(cardManager);
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                throw new IllegalArgumentException();
            }

            this.keyPair = keyPair;
            this.sigType = sigType;
            this.export = export;
            this.raw = raw;

            int len = raw != null ? raw.length : 0;
            byte[] data = new byte[3 + len];
            data[0] = sigType;
            ByteUtil.setShort(data, 1, (short) len);
            if (raw != null) {
                System.arraycopy(raw, 0, data, 3, len);
            }

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_ECDSA_SIGN, keyPair, export, data);
        }

        @Override
        public Response.ECDSA send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.ECDSA(response, getDescription(), elapsed, keyPair, sigType, export, raw);
        }

        @Override
        public String getDescription() {
            String algo = CardUtil.getSigTypeString(sigType);
            String key = keyPair == ECTesterApplet.KEYPAIR_LOCAL ? "local" : "remote";
            String data = raw == null ? "random" : "provided";
            return String.format("%s signature with %s keypair(%s data)", algo, key, data);
        }
    }

    public static class ECDSA_verify extends Command {
        private byte keyPair;
        private byte sigType;
        private byte[] raw;
        private byte[] signature;

        /**
         * Creates the INS_ECDSA_VERIFY instruction.
         *
         * @param cardManager cardManager to send APDU through
         * @param keyPair     keyPair to use for signing and verification (KEYPAIR_LOCAL || KEYPAIR_REMOTE)
         * @param sigType     Signature type to use
         * @param raw         data to sign
         * @param signature   signature data
         */
        public ECDSA_verify(CardMngr cardManager, byte keyPair, byte sigType, byte[] raw, byte[] signature) {
            super(cardManager);
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                throw new IllegalArgumentException();
            }
            if (raw == null || signature == null) {
                throw new IllegalArgumentException();
            }

            this.keyPair = keyPair;
            this.sigType = sigType;
            this.raw = raw;
            this.signature = signature;

            byte[] data = new byte[4 + raw.length + signature.length];
            ByteUtil.setShort(data, 0, (short) raw.length);
            System.arraycopy(raw, 0, data, 2, raw.length);
            ByteUtil.setShort(data, 2 + raw.length, (short) signature.length);
            System.arraycopy(signature, 0, data, 2 + raw.length + 2, signature.length);

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_ECDSA_VERIFY, keyPair, sigType, data);
        }

        @Override
        public Response.ECDSA send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.ECDSA(response, getDescription(), elapsed, keyPair, sigType, ECTesterApplet.EXPORT_FALSE, raw);
        }

        @Override
        public String getDescription() {
            String algo = CardUtil.getSigTypeString(sigType);
            String key = keyPair == ECTesterApplet.KEYPAIR_LOCAL ? "local" : "remote";
            String data = raw == null ? "random" : "provided";
            return String.format("%s verification with %s keypair(%s data)", algo, key, data);
        }
    }

    /**
     *
     */
    public static class Cleanup extends Command {

        /**
         * @param cardManager cardManager to send APDU through
         */
        public Cleanup(CardMngr cardManager) {
            super(cardManager);

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_CLEANUP, 0, 0, GOD_DAMN_JAVA_BUG_6474858_AND_GOD_DAMN_JAVA_12_MODULE_SYSTEM);
        }

        @Override
        public Response.Cleanup send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.Cleanup(response, getDescription(), elapsed);
        }

        @Override
        public String getDescription() {
            return "Request JCSystem object deletion";
        }
    }

    /**
     *
     */
    public static class GetInfo extends Command {

        /**
         * @param cardManager cardManager to send APDU through
         */
        public GetInfo(CardMngr cardManager) {
            super(cardManager);

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_GET_INFO, 0, 0, GOD_DAMN_JAVA_BUG_6474858_AND_GOD_DAMN_JAVA_12_MODULE_SYSTEM);
        }

        @Override
        public Response.GetInfo send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.GetInfo(response, getDescription(), elapsed);
        }

        @Override
        public String getDescription() {
            return "Get applet info";
        }
    }

    /**
     *
     */
    public static class SetDryRunMode extends Command {
        private byte dryRunMode;

        /**
         * @param cardManager
         * @param dryRunMode
         */
        public SetDryRunMode(CardMngr cardManager, byte dryRunMode) {
            super(cardManager);
            this.dryRunMode = dryRunMode;

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_SET_DRY_RUN_MODE, dryRunMode, 0, GOD_DAMN_JAVA_BUG_6474858_AND_GOD_DAMN_JAVA_12_MODULE_SYSTEM);
        }

        @Override
        public Response.SetDryRunMode send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.SetDryRunMode(response, getDescription(), elapsed);
        }

        @Override
        public String getDescription() {
            return (dryRunMode == ECTesterApplet.MODE_NORMAL ? "Disable" : "Enable") + " dry run mode";
        }
    }
}

