package cz.crcs.ectester.reader;

import cz.crcs.ectester.applet.ECTesterApplet;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class Command {
    protected CommandAPDU cmd;
    protected CardMngr cardManager;

    protected Command(CardMngr cardManager) {
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

    /**
     *
     */
    public static class Allocate extends Command {
        private byte keyPair;
        private short keyLength;
        private byte keyClass;

        /**
         * Creates the INS_ALLOCATE instruction.
         *
         * @param cardManager
         * @param keyPair     which keyPair to use, local/remote (KEYPAIR_* | ...)
         * @param keyLength   key length to set
         * @param keyClass    key class to allocate
         */
        public Allocate(CardMngr cardManager, byte keyPair, short keyLength, byte keyClass) {
            super(cardManager);
            this.keyPair = keyPair;
            this.keyLength = keyLength;
            this.keyClass = keyClass;

            byte[] data = new byte[]{0, 0, keyClass};
            Util.setShort(data, 0, keyLength);
            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_ALLOCATE, keyPair, 0x00, data);
        }

        @Override
        public Response.Allocate send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.Allocate(response, elapsed, keyPair, keyLength, keyClass);
        }
    }

    /**
     *
     */
    public static class Clear extends Command {
        private byte keyPair;

        /**
         * @param cardManager
         * @param keyPair     which keyPair clear, local/remote (KEYPAIR_* || ...)
         */
        public Clear(CardMngr cardManager, byte keyPair) {
            super(cardManager);
            this.keyPair = keyPair;

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_CLEAR, keyPair, 0x00);
        }

        @Override
        public Response.Clear send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.Clear(response, elapsed, keyPair);
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
         * @param cardManager
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
            Util.setShort(data, 0, params);
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
            return new Response.Set(response, elapsed, keyPair, curve, params);
        }
    }

    /**
     *
     */
    public static class Corrupt extends Command {
        private byte keyPair;
        private byte key;
        private short params;
        private byte corruption;

        /**
         * @param cardManager
         * @param keyPair     which keyPair to corrupt, local/remote (KEYPAIR_* || ...)
         * @param key
         * @param params      parameters to corrupt (EC_Consts.PARAMETER_* | ...)
         * @param corruption  corruption type (EC_Consts.CORRUPTION_*)
         */
        protected Corrupt(CardMngr cardManager, byte keyPair, byte key, short params, byte corruption) {
            super(cardManager);
            this.keyPair = keyPair;
            this.key = key;
            this.params = params;
            this.corruption = corruption;

            byte[] data = new byte[3];
            Util.setShort(data, 0, params);
            data[2] = corruption;

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_CORRUPT, keyPair, key, data);
        }

        @Override
        public Response.Corrupt send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.Corrupt(response, elapsed, keyPair, key, params, corruption);
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
         * @param cardManager
         * @param keyPair     which keyPair to generate, local/remote (KEYPAIR_* || ...)
         */
        public Generate(CardMngr cardManager, byte keyPair) {
            super(cardManager);
            this.keyPair = keyPair;

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_GENERATE, keyPair, 0);
        }

        @Override
        public Response.Generate send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.Generate(response, elapsed, keyPair);
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
         * @param cardManager
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
            Util.setShort(data, 0, params);

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_EXPORT, keyPair, key, data);
        }

        @Override
        public Response.Export send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.Export(response, elapsed, keyPair, key, params);
        }
    }

    /**
     *
     */
    public static class ECDH extends Command {
        private byte pubkey;
        private byte privkey;
        private byte export;
        private byte corruption;

        /**
         * Creates the INS_ECDH instruction.
         *
         * @param cardManager
         * @param pubkey      keyPair to use for public key, (KEYPAIR_LOCAL || KEYPAIR_REMOTE)
         * @param privkey     keyPair to use for private key, (KEYPAIR_LOCAL || KEYPAIR_REMOTE)
         * @param export      whether to export ECDH secret
         * @param corruption  whether to invalidate the pubkey before ECDH (EC_Consts.CORRUPTION_* || ...)
         */
        public ECDH(CardMngr cardManager, byte pubkey, byte privkey, byte export, byte corruption) {
            super(cardManager);
            this.pubkey = pubkey;
            this.privkey = privkey;
            this.export = export;
            this.corruption = corruption;

            byte[] data = new byte[]{export, corruption};

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_ECDH, pubkey, privkey, data);
        }

        @Override
        public Response.ECDH send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.ECDH(response, elapsed, pubkey, privkey, export, corruption);
        }
    }

    public static class ECDSA extends Command {
        private byte keyPair;
        private byte export;
        private byte[] raw;

        /**
         * Creates the INS_ECDSA instruction.
         *
         * @param cardManager
         * @param keyPair     keyPair to use for signing and verification (KEYPAIR_LOCAL || KEYPAIR_REMOTE)
         * @param export      whether to export ECDSA signature
         * @param raw         data to sign, can be null, in which case random data is signed.
         */
        public ECDSA(CardMngr cardManager, byte keyPair, byte export, byte[] raw) {
            super(cardManager);
            this.keyPair = keyPair;
            this.export = export;
            this.raw = raw;

            int len = raw != null ? raw.length : 0;
            byte[] data = new byte[2 + len];
            Util.setShort(data, 0, (short) len);
            if (raw != null) {
                System.arraycopy(raw, 0, data, 2, len);
            }

            this.cmd = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_ECDSA, keyPair, export, data);
        }

        @Override
        public Response.ECDSA send() throws CardException {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cardManager.send(cmd);
            elapsed += System.nanoTime();
            return new Response.ECDSA(response, elapsed, keyPair, export, raw);
        }
    }
}

