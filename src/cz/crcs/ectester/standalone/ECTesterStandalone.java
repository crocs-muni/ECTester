/*
 * ECTester, tool for testing Elliptic curve cryptography implementations.
 * Copyright (c) 2016-2018 Petr Svenda <petr@svenda.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package cz.crcs.ectester.standalone;

import cz.crcs.ectester.common.cli.*;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.TestException;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.common.util.ECUtil;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.standalone.consts.KeyAgreementIdent;
import cz.crcs.ectester.standalone.consts.KeyPairGeneratorIdent;
import cz.crcs.ectester.standalone.consts.SignatureIdent;
import cz.crcs.ectester.standalone.libs.*;
import cz.crcs.ectester.standalone.output.TextTestWriter;
import cz.crcs.ectester.standalone.output.XMLTestWriter;
import cz.crcs.ectester.standalone.output.YAMLTestWriter;
import cz.crcs.ectester.standalone.test.StandaloneDefaultSuite;
import cz.crcs.ectester.standalone.test.StandaloneTestSuite;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import javax.crypto.KeyAgreement;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Standalone part of ECTester, a tool for testing Elliptic curve implementations in software libraries.
 *
 * @author Jan Jancar johny@neuromancer.sk
 * @version v0.2.0
 */
public class ECTesterStandalone {
    private ProviderECLibrary[] libs = new ProviderECLibrary[]{new SunECLib(), new BouncyCastleLib(), new TomcryptLib(), new BotanLib()};
    private Config cfg;

    private Options opts = new Options();
    private TreeParser optParser;
    private TreeCommandLine cli;
    private static final String VERSION = "v0.2.0";
    private static final String DESCRIPTION = "ECTesterStandalone " + VERSION + ", an Elliptic Curve Cryptography support tester/utility.";
    private static final String LICENSE = "MIT Licensed\nCopyright (c) 2016-2017 Petr Svenda <petr@svenda.com>";
    private static final String CLI_HEADER = "\n" + DESCRIPTION + "\n\n";
    private static final String CLI_FOOTER = "\n" + LICENSE;

    private void run(String[] args) {
        try {
            cli = parseArgs(args);

            if (cli.hasOption("version")) {
                CLITools.version(DESCRIPTION, LICENSE);
                return;
            } else if (cli.hasOption("help") || cli.getNext() == null) {
                CLITools.help("ECTesterStandalone.jar", CLI_HEADER, opts, optParser, CLI_FOOTER, true);
                return;
            }

            for (ECLibrary lib : libs) {
                lib.initialize();
            }

            cfg = new Config(libs);
            if (!cfg.readOptions(cli)) {
                return;
            }

            if (cli.isNext("list-libs")) {
                listLibraries();
            } else if (cli.isNext("list-data")) {
                CLITools.listNamed(EC_Store.getInstance(), cli.getNext().getArg(0));
            } else if (cli.isNext("ecdh")) {
                ecdh();
            } else if (cli.isNext("ecdsa")) {
                ecdsa();
            } else if (cli.isNext("generate")) {
                generate();
            } else if (cli.isNext("test")) {
                test();
            } else if (cli.isNext("export")) {
                export();
            }

        } catch (ParseException | ParserConfigurationException | IOException ex) {
            System.err.println(ex.getMessage());
        } catch (InvalidAlgorithmParameterException | InvalidParameterException e) {
            System.err.println("Invalid algorithm parameter: " + e.getMessage());
        } catch (NoSuchAlgorithmException nsaex) {
            System.err.println("Algorithm not supported by the selected library: " + nsaex.getMessage());
            nsaex.printStackTrace();
        } catch (InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
    }

    private TreeCommandLine parseArgs(String[] args) throws ParseException {
        Map<String, ParserOptions> actions = new TreeMap<>();

        Option namedCurve = Option.builder("nc").longOpt("named-curve").desc("Use a named curve, from CurveDB: <cat/id>").hasArg().argName("cat/id").build();
        Option bits = Option.builder("b").longOpt("bits").hasArg().argName("n").optionalArg(false).desc("What size of curve to use.").build();

        Options testOpts = new Options();
        testOpts.addOption(bits);
        testOpts.addOption(namedCurve);
        testOpts.addOption(Option.builder("gt").longOpt("kpg-type").desc("Set the KeyPairGenerator object [type].").hasArg().argName("type").optionalArg(false).build());
        testOpts.addOption(Option.builder("kt").longOpt("ka-type").desc("Set the KeyAgreement object [type].").hasArg().argName("type").optionalArg(false).build());
        testOpts.addOption(Option.builder("st").longOpt("sig-type").desc("Set the Signature object [type].").hasArg().argName("type").optionalArg(false).build());
        testOpts.addOption(Option.builder("f").longOpt("format").desc("Set the output format, one of text,yaml,xml.").hasArg().argName("format").optionalArg(false).build());
        List<Argument> testArgs = new LinkedList<>();
        testArgs.add(new Argument("test_suite", "The test suite to run.", true));
        ParserOptions test = new ParserOptions(new DefaultParser(), testOpts, testArgs);
        actions.put("test", test);

        Options ecdhOpts = new Options();
        ecdhOpts.addOption(bits);
        ecdhOpts.addOption(namedCurve);
        ecdhOpts.addOption(Option.builder("t").longOpt("type").desc("Set KeyAgreement object [type].").hasArg().argName("type").optionalArg(false).build());
        ecdhOpts.addOption(Option.builder("n").longOpt("amount").hasArg().argName("amount").optionalArg(false).desc("Do ECDH [amount] times.").build());
        ParserOptions ecdh = new ParserOptions(new DefaultParser(), ecdhOpts);
        actions.put("ecdh", ecdh);

        Options ecdsaOpts = new Options();
        ecdsaOpts.addOption(bits);
        ecdsaOpts.addOption(namedCurve);
        ecdsaOpts.addOption(Option.builder("t").longOpt("type").desc("Set Signature object [type].").hasArg().argName("type").optionalArg(false).build());
        ecdsaOpts.addOption(Option.builder("n").longOpt("amount").hasArg().argName("amount").optionalArg(false).desc("Do ECDSA [amount] times.").build());
        ecdsaOpts.addOption(Option.builder("f").longOpt("file").hasArg().argName("file").optionalArg(false).desc("Input [file] to sign.").build());
        ParserOptions ecdsa = new ParserOptions(new DefaultParser(), ecdsaOpts);
        actions.put("ecdsa", ecdsa);

        Options generateOpts = new Options();
        generateOpts.addOption(bits);
        generateOpts.addOption(namedCurve);
        generateOpts.addOption(Option.builder("n").longOpt("amount").hasArg().argName("amount").optionalArg(false).desc("Generate [amount] of EC keys.").build());
        generateOpts.addOption(Option.builder("t").longOpt("type").hasArg().argName("type").optionalArg(false).desc("Set KeyPairGenerator object [type].").build());
        ParserOptions generate = new ParserOptions(new DefaultParser(), generateOpts);
        actions.put("generate", generate);

        Options exportOpts = new Options();
        exportOpts.addOption(Option.builder("t").longOpt("type").hasArg().argName("type").optionalArg(false).desc("Set KeyPair object [type].").build());
        exportOpts.addOption(bits);
        ParserOptions export = new ParserOptions(new DefaultParser(), exportOpts);
        actions.put("export", export);

        Options listDataOpts = new Options();
        List<Argument> listDataArgs = new LinkedList<>();
        listDataArgs.add(new Argument("what", "what to list.", false));
        ParserOptions listData = new ParserOptions(new TreeParser(Collections.emptyMap(), false, listDataArgs), listDataOpts);
        actions.put("list-data", listData);

        Options listLibsOpts = new Options();
        ParserOptions listLibs = new ParserOptions(new DefaultParser(), listLibsOpts);
        actions.put("list-libs", listLibs);

        List<Argument> baseArgs = new LinkedList<>();
        baseArgs.add(new Argument("lib", "What library to use.", false));
        optParser = new TreeParser(actions, false, baseArgs);

        opts.addOption(Option.builder("V").longOpt("version").desc("Print version info.").build());
        opts.addOption(Option.builder("h").longOpt("help").desc("Print help.").build());

        return optParser.parse(opts, args);
    }

    /**
     *
     */
    private void listLibraries() {
        for (ECLibrary lib : libs) {
            if (lib.isInitialized() && (cfg.selected == null || lib == cfg.selected)) {
                System.out.println("\t- " + lib.name());
                Set<KeyPairGeneratorIdent> kpgs = lib.getKPGs();
                if (!kpgs.isEmpty()) {
                    System.out.println("\t\t- KeyPairGenerators: " + String.join(",", kpgs.stream().map(KeyPairGeneratorIdent::getName).collect(Collectors.toList())));
                }
                Set<KeyAgreementIdent> eckas = lib.getKAs();
                if (!eckas.isEmpty()) {
                    System.out.println("\t\t- KeyAgreements: " + String.join(",", eckas.stream().map(KeyAgreementIdent::getName).collect(Collectors.toList())));
                }
                Set<SignatureIdent> sigs = lib.getSigs();
                if (!sigs.isEmpty()) {
                    System.out.println("\t\t- Signatures: " + String.join(",", sigs.stream().map(SignatureIdent::getName).collect(Collectors.toList())));
                }
                Set<String> curves = lib.getCurves();
                if (!curves.isEmpty()) {
                    System.out.println("\t\t- Curves: " + String.join(",", curves));
                }
                System.out.println();
            }
        }
    }

    /**
     *
     */
    private void ecdh() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        ProviderECLibrary lib = cfg.selected;

        String algo = cli.getOptionValue("ecdh.type", "ECDH");
        KeyAgreementIdent kaIdent = lib.getKAs().stream()
                .filter((ident) -> ident.contains(algo))
                .findFirst()
                .orElse(null);

        KeyPairGeneratorIdent kpIdent = lib.getKPGs().stream()
                .filter((ident) -> ident.contains(algo))
                .findFirst()
                .orElse(lib.getKPGs().stream()
                        .filter((ident) -> ident.contains("ECDH"))
                        .findFirst()
                        .orElse(lib.getKPGs().stream()
                                .filter((ident) -> ident.contains("EC"))
                                .findFirst()
                                .orElse(null)));


        if (kaIdent == null || kpIdent == null) {
            throw new NoSuchAlgorithmException(algo);
        } else {
            KeyAgreement ka = kaIdent.getInstance(lib.getProvider());
            KeyPairGenerator kpg = kpIdent.getInstance(lib.getProvider());
            AlgorithmParameterSpec spec = null;
            if (cli.hasOption("ecdh.bits")) {
                int bits = Integer.parseInt(cli.getOptionValue("ecdh.bits"));
                kpg.initialize(bits);
            } else if (cli.hasOption("ecdh.named-curve")) {
                String curveName = cli.getOptionValue("ecdh.named-curve");
                EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, curveName);
                if (curve == null) {
                    System.err.println("Curve not found: " + curveName);
                    return;
                }
                spec = curve.toSpec();
                kpg.initialize(spec);
            }//TODO: allow ECGenNamedSpec

            System.out.println("index;nanotime;pubW;privS;secret");

            int amount = Integer.parseInt(cli.getOptionValue("ecdh.amount", "1"));
            for (int i = 0; i < amount; ++i) {
                KeyPair one = kpg.genKeyPair();
                KeyPair other = kpg.genKeyPair();

                ECPrivateKey privkey = (ECPrivateKey) one.getPrivate();
                ECPublicKey pubkey = (ECPublicKey) other.getPublic();

                long elapsed = -System.nanoTime();
                if (spec != null) {
                    ka.init(privkey, spec);
                } else {
                    ka.init(privkey);
                }
                ka.doPhase(pubkey, true);
                elapsed += System.nanoTime();
                byte[] result = ka.generateSecret();
                ka = kaIdent.getInstance(lib.getProvider());

                String pub = ByteUtil.bytesToHex(ECUtil.toX962Uncompressed(pubkey.getW(), pubkey.getParams()), false);
                String priv = ByteUtil.bytesToHex(privkey.getS().toByteArray(), false);
                String dh = ByteUtil.bytesToHex(result, false);
                System.out.println(String.format("%d;%d;%s;%s;%s", i, elapsed, pub, priv, dh));
            }
        }
    }

    /**
     *
     */
    private void ecdsa() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, SignatureException {
        byte[] data;
        String dataString;
        if (cli.hasOption("ecdsa.file")) {
            String fileName = cli.getOptionValue("ecdsa.file");
            File in = new File(fileName);
            long len = in.length();
            if (len == 0) {
                throw new FileNotFoundException(fileName);
            }
            data = Files.readAllBytes(in.toPath());
            dataString = "";
        } else {
            SecureRandom random = new SecureRandom();
            data = new byte[32];
            random.nextBytes(data);
            dataString = ByteUtil.bytesToHex(data, false);
        }

        ProviderECLibrary lib = cfg.selected;

        String algo = cli.getOptionValue("ecdsa.type", "ECDSA");
        SignatureIdent sigIdent = lib.getSigs().stream()
                .filter((ident) -> ident.contains(algo))
                .findFirst()
                .orElse(null);

        KeyPairGeneratorIdent kpIdent = lib.getKPGs().stream()
                .filter((ident) -> ident.contains(algo))
                .findFirst()
                .orElse(lib.getKPGs().stream()
                        .filter((ident) -> ident.contains("EC"))
                        .findFirst()
                        .orElse(null));

        if (sigIdent == null || kpIdent == null) {
            throw new NoSuchAlgorithmException(algo);
        } else {
            Signature sig = sigIdent.getInstance(lib.getProvider());
            KeyPairGenerator kpg = kpIdent.getInstance(lib.getProvider());
            if (cli.hasOption("ecdsa.bits")) {
                int bits = Integer.parseInt(cli.getOptionValue("ecdsa.bits"));
                kpg.initialize(bits);
            } else if (cli.hasOption("ecdsa.named-curve")) {
                String curveName = cli.getOptionValue("ecdsa.named-curve");
                EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, curveName);
                if (curve == null) {
                    System.err.println("Curve not found: " + curveName);
                    return;
                }
                kpg.initialize(curve.toSpec());
            }

            System.out.println("index;data;signtime;verifytime;pubW;privS;signature;verified");

            int amount = Integer.parseInt(cli.getOptionValue("ecdsa.amount", "1"));
            for (int i = 0; i < amount; ++i) {
                KeyPair one = kpg.genKeyPair();

                ECPrivateKey privkey = (ECPrivateKey) one.getPrivate();
                ECPublicKey pubkey = (ECPublicKey) one.getPublic();

                sig.initSign(privkey);
                sig.update(data);

                long signTime = -System.nanoTime();
                byte[] signature = sig.sign();
                signTime += System.nanoTime();

                sig.initVerify(pubkey);
                sig.update(data);

                long verifyTime = -System.nanoTime();
                boolean verified = sig.verify(signature);
                verifyTime += System.nanoTime();


                String pub = ByteUtil.bytesToHex(ECUtil.toX962Uncompressed(pubkey.getW(), pubkey.getParams()), false);
                String priv = ByteUtil.bytesToHex(privkey.getS().toByteArray(), false);
                String sign = ByteUtil.bytesToHex(signature, false);
                System.out.println(String.format("%d;%s;%d;%d;%s;%s;%s;%d", i, dataString, signTime, verifyTime, pub, priv, sign, verified ? 1 : 0));
            }
        }
    }

    /**
     *
     */
    private void generate() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ProviderECLibrary lib = cfg.selected;
        KeyPairGeneratorIdent ident = null;
        String algo = cli.getOptionValue("generate.type", "EC");
        for (KeyPairGeneratorIdent kpIdent : lib.getKPGs()) {
            if (kpIdent.contains(algo)) {
                ident = kpIdent;
                break;
            }
        }
        if (ident == null) {
            throw new NoSuchAlgorithmException(algo);
        } else {
            KeyPairGenerator kpg = ident.getInstance(lib.getProvider());
            if (cli.hasOption("generate.bits")) {
                int bits = Integer.parseInt(cli.getOptionValue("generate.bits"));
                kpg.initialize(bits);
            } else if (cli.hasOption("generate.named-curve")) {
                String curveName = cli.getOptionValue("generate.named-curve");
                EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, curveName);
                if (curve == null) {
                    System.err.println("Curve not found: " + curveName);
                    return;
                }
                kpg.initialize(curve.toSpec());
            }
            System.out.println("index;nanotime;pubW;privS");

            int amount = Integer.parseInt(cli.getOptionValue("generate.amount", "1"));
            for (int i = 0; i < amount; ++i) {
                long elapsed = -System.nanoTime();
                KeyPair kp = kpg.genKeyPair();
                elapsed += System.nanoTime();
                ECPublicKey publicKey = (ECPublicKey) kp.getPublic();
                ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();

                String pub = ByteUtil.bytesToHex(ECUtil.toX962Uncompressed(publicKey.getW(), publicKey.getParams()), false);
                String priv = ByteUtil.bytesToHex(privateKey.getS().toByteArray(), false);
                System.out.println(String.format("%d;%d;%s;%s", i, elapsed, pub, priv));
            }
        }
    }

    /**
     *
     */
    private void test() throws TestException, ParserConfigurationException {
        TestWriter writer;
        switch (cli.getOptionValue("test.format", "text").toLowerCase()) {
            case "yaml":
            case "yml":
                writer = new YAMLTestWriter(System.out);
                break;
            case "xml":
                writer = new XMLTestWriter(System.out);
                break;
            case "text":
            default:
                writer = new TextTestWriter(System.out);
                break;
        }

        StandaloneTestSuite suite = new StandaloneDefaultSuite(writer, cfg, cli);
        suite.run();
    }

    /**
     *
     */
    private void export() throws NoSuchAlgorithmException, IOException {
        ProviderECLibrary lib = cfg.selected;
        KeyPairGeneratorIdent ident = null;
        String algo = cli.getOptionValue("export.type", "EC");
        for (KeyPairGeneratorIdent kpIdent : lib.getKPGs()) {
            if (kpIdent.contains(algo)) {
                ident = kpIdent;
                break;
            }
        }
        if (ident == null) {
            throw new NoSuchAlgorithmException(algo);
        } else {
            KeyPairGenerator kpg = ident.getInstance(lib.getProvider());
            if (cli.hasOption("export.bits")) {
                int bits = Integer.parseInt(cli.getOptionValue("export.bits"));
                kpg.initialize(bits);
            }
            KeyPair kp = kpg.genKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();
            ECParameterSpec params = privateKey.getParams();
            System.out.println(params);
            EC_Curve curve = EC_Curve.fromSpec(params);
            curve.writeCSV(System.out);
        }
    }

    public static void main(String[] args) {
        ECTesterStandalone app = new ECTesterStandalone();
        app.run(args);
    }


    /**
     *
     */
    public static class Config {
        private ProviderECLibrary[] libs;
        public ProviderECLibrary selected = null;

        public Config(ProviderECLibrary[] libs) {
            this.libs = libs;
        }

        boolean readOptions(TreeCommandLine cli) {
            if (cli.isNext("generate") || cli.isNext("export") || cli.isNext("ecdh") || cli.isNext("ecdsa") || cli.isNext("test")) {
                if (!cli.hasArg(-1)) {
                    System.err.println("Missing library name argument.");
                    return false;
                }

                String next = cli.getNextName();
                if (cli.hasOption(next + ".bits") && cli.hasOption(next + ".named-curve")) {
                    System.err.println("You can only specify bitsize or a named curve, nor both.");
                    return false;
                }
            }

            String libraryName = cli.getArg(-1);
            if (libraryName != null) {
                List<ProviderECLibrary> matchedLibs = new LinkedList<>();
                for (ProviderECLibrary lib : libs) {
                    if (lib.name().toLowerCase().contains(libraryName.toLowerCase())) {
                        matchedLibs.add(lib);
                    }
                }
                if (matchedLibs.size() == 0) {
                    System.err.println("No library " + libraryName + " found.");
                    return false;
                } else if (matchedLibs.size() > 1) {
                    System.err.println("Multiple matching libraries found: " + String.join(",", matchedLibs.stream().map(ECLibrary::name).collect(Collectors.toList())));
                    return false;
                } else {
                    selected = matchedLibs.get(0);
                }
            }

            if (cli.hasOption("test.format")) {
                String fmt = cli.getOptionValue("test.format");
                String formats[] = new String[]{"text", "xml", "yaml", "yml"};
                if (!Arrays.asList(formats).contains(fmt.toLowerCase())) {
                    System.err.println("Invalid format specified.");
                    return false;
                }
            }

            return true;
        }
    }
}
