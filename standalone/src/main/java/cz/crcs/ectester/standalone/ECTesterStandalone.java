/*
 * ECTester, tool for testing Elliptic curve cryptography implementations.
 * Copyright (c) 2016-2018 Petr Svenda <petr@svenda.com>
 * Copyright (c) 2016-2019 Jan Jancar  <johny@neuromancer.sk>
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
import cz.crcs.ectester.common.ec.EC_Consts;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.TestException;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.common.util.ECUtil;
import cz.crcs.ectester.common.util.FileUtil;
import cz.crcs.ectester.common.util.Util;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.standalone.consts.KeyAgreementIdent;
import cz.crcs.ectester.standalone.consts.KeyPairGeneratorIdent;
import cz.crcs.ectester.standalone.consts.SignatureIdent;
import cz.crcs.ectester.standalone.libs.*;
import cz.crcs.ectester.standalone.libs.jni.SignalException;
import cz.crcs.ectester.standalone.libs.jni.TimeoutException;
import cz.crcs.ectester.standalone.output.FileTestWriter;
import cz.crcs.ectester.standalone.test.suites.*;
import org.apache.commons.cli.*;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Standalone part of ECTester, a tool for testing Elliptic curve implementations in software libraries.
 *
 * @author Jan Jancar johny@neuromancer.sk
 * @version v0.3.3
 */
public class ECTesterStandalone {
    private ProviderECLibrary[] libs;
    private Config cfg;

    private final Options opts = new Options();
    private TreeParser optParser;
    private TreeCommandLine cli;
    public static final String VERSION = "v0.3.3";
    private static final String DESCRIPTION = "ECTesterStandalone " + VERSION + ", an Elliptic Curve Cryptography support tester/utility.";
    private static final String LICENSE = "MIT Licensed\nCopyright © 2016-2019 Petr Svenda <petr@svenda.com>\nCopyright © 2016-2019 Jan Jancar  <johny@neuromancer.sk>";
    private static final String CLI_HEADER = "\n" + DESCRIPTION + "\n\n";
    private static final String CLI_FOOTER = "\n" + LICENSE;

    public static final String LIB_RESOURCE_DIR = "/cz/crcs/ectester/standalone/libs/jni/";

    private void run(String[] args) {
        try {
            cli = parseArgs(args);

            if (cli.hasOption("version")) {
                CLITools.version(DESCRIPTION, LICENSE);
                return;
            } else if (cli.hasOption("help") || cli.getNext() == null) {
                String command = cli.getOptionValue("help");
                if (command == null) {
                    CLITools.help("ECTesterStandalone.jar", CLI_HEADER, opts, optParser, CLI_FOOTER, true);
                } else {
                    CLITools.help(CLI_HEADER, optParser, CLI_FOOTER, command);
                }
                return;
            }

            Path reqs = FileUtil.getRequirementsDir();
            reqs.toFile().mkdirs();

            if (!System.getProperty("os.name").startsWith("Windows")) {
                FileUtil.write(LIB_RESOURCE_DIR + "lib_timing.so", reqs.resolve("lib_timing.so"));
                FileUtil.write(LIB_RESOURCE_DIR + "lib_preload.so", reqs.resolve("lib_preload.so"));
                FileUtil.write(LIB_RESOURCE_DIR + "lib_prng.so", reqs.resolve("lib_prng.so"));
                FileUtil.write(LIB_RESOURCE_DIR + "lib_csignals.so", reqs.resolve("lib_csignals.so"));
                FileUtil.write(LIB_RESOURCE_DIR + "lib_cppsignals.so", reqs.resolve("lib_cppsignals.so"));

                String preloadLibPath = reqs.resolve("lib_preload.so").toAbsolutePath().toString();
                String preload = System.getenv("LD_PRELOAD");
                if (preload == null && !cli.hasOption("no-preload")) {
                    ProcessBuilder builder = new ProcessBuilder();
                    Map<String, String> env = builder.environment();
                    env.put("LD_PRELOAD", preloadLibPath);

                    ProcessHandle.Info info = ProcessHandle.current().info();
                    List<String> argList = new LinkedList<>();
                    if (info.command().isPresent()) {
                        argList.add(info.command().get());
                    } else {
                        System.err.println("Cannot locate command to spawn preloaded-subprocess.");
                        return;
                    }
                    if (info.arguments().isPresent()) {
                        argList.addAll(List.of(info.arguments().get()));
                    } else {
                        System.err.println("Cannot locate arguments to spawn preloaded-subprocess.");
                        return;
                    }
                    builder.command(argList);
                    builder.inheritIO();

                    Process process = builder.start();
                    int result;
                    while (true) {
                        try {
                            result = process.waitFor();
                            break;
                        } catch (InterruptedException ignored) {
                        }
                    }
                    System.exit(result);
                } else {
                    // Load the utility libs.
                    System.load(reqs.resolve("lib_prng.so").toString());
                    System.load(reqs.resolve("lib_timing.so").toString());
                    System.load(reqs.resolve("lib_csignals.so").toString());
                    System.load(reqs.resolve("lib_cppsignals.so").toString());
                }
            }

            List<ProviderECLibrary> libObjects = new LinkedList<>();
            Class<?>[] libClasses = new Class[]{SunECLib.class,
                    BouncyCastleLib.class,
                    TomcryptLib.class,
                    BotanLib.class,
                    CryptoppLib.class,
                    OpensslLib.class,
                    BoringsslLib.class,
                    GcryptLib.class,
                    MscngLib.class,
                    WolfCryptLib.class,
                    MbedTLSLib.class,
                    IppcpLib.class,
                    NettleLib.class,
                    LibresslLib.class};
            for (Class<?> c : libClasses) {
                try {
                    libObjects.add((ProviderECLibrary) c.getDeclaredConstructor().newInstance());
                } catch (NoSuchMethodException | InstantiationException | IllegalAccessException |
                         InvocationTargetException ignored) {
                }
            }
            libs = libObjects.toArray(new ProviderECLibrary[0]);

            cfg = new Config(libs);
            if (!cfg.readOptions(cli)) {
                return;
            }

            if (cli.isNext("list-libs")) {
                listLibraries();
            } else if (cli.isNext("list-data")) {
                CLITools.listNamed(EC_Store.getInstance(), cli.getNext().getArg(0));
            } else if (cli.isNext("list-suites")) {
                listSuites();
            } else if (cli.isNext("list-types")) {
                listIdents();
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
        } catch (InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
    }

    private TreeCommandLine parseArgs(String[] args) throws ParseException {
        Map<String, ParserOptions> actions = new TreeMap<>();

        Option namedCurve = Option.builder("nc").longOpt("named-curve").desc("Use a named curve, from CurveDB: <cat/id>").hasArg().argName("cat/id").optionalArg(false).numberOfArgs(1).build();
        Option namedPublic = Option.builder("npub").longOpt("named-public").desc("Use a named public key, from CurveDB: <cat/id>").hasArg().argName("cat/id").optionalArg(false).numberOfArgs(1).build();
        Option filePublic = Option.builder("pub").longOpt("public").desc("Use a given public key from file.").hasArg().argName("pubkey").optionalArg(false).numberOfArgs(1).build();
        OptionGroup publicKey = new OptionGroup();
        publicKey.addOption(namedPublic);
        publicKey.addOption(filePublic);
        Option namedPrivate = Option.builder("npriv").longOpt("named-private").desc("Use a named private key, from CurveDB: <cat/id>").hasArg().argName("cat/id").optionalArg(false).numberOfArgs(1).build();
        Option filePrivate = Option.builder("priv").longOpt("private").desc("Use a given private key from file.").hasArg().argName("privkey").optionalArg(false).numberOfArgs(1).build();
        OptionGroup privateKey = new OptionGroup();
        privateKey.addOption(namedPrivate);
        privateKey.addOption(filePrivate);
        Option curveName = Option.builder("cn").longOpt("curve-name").desc("Use a named curve, search from curves supported by the library: <name>").hasArg().argName("name").optionalArg(false).numberOfArgs(1).build();
        Option bits = Option.builder("b").longOpt("bits").hasArg().argName("n").optionalArg(false).desc("What size of curve to use.").numberOfArgs(1).build();
        Option output = Option.builder("o").longOpt("output").desc("Output into file <output_file>. The file can be prefixed by the format (one of text,yml,xml), such as: xml:<output_file>.").hasArgs().argName("output_file").optionalArg(false).numberOfArgs(1).build();
        Option outputRaw = Option.builder("o").longOpt("output").desc("Output CSV into file <output_file>.").hasArgs().argName("output_file").optionalArg(false).numberOfArgs(1).build();
        Option quiet = Option.builder("q").longOpt("quiet").desc("Do not output to stdout.").build();
        Option timeSource = Option.builder("ts").longOpt("time-source").desc("Use a given native timing source: {rdtsc, monotonic, monotonic-raw, cputime-process, cputime-thread}").hasArgs().argName("source").optionalArg(false).numberOfArgs(1).build();
        Option prngSeed = Option.builder("ps").longOpt("prng-seed").desc("Use a deterministic PRNG with the given [seed] (hexadecimal) in the library.").hasArgs().argName("seed").optionalArg(false).numberOfArgs(1).build();
        Option file = Option.builder("f").longOpt("file").hasArg().argName("file").optionalArg(false).desc("Input [file] to sign.").build();
        Option message = Option.builder("d").longOpt("data").desc("Sign the given [message].").hasArgs().argName("message").optionalArg(false).numberOfArgs(1).build();
        Option messageSeed = Option.builder("ds").longOpt("data-seed").desc("Use a deterministic PRNG with the given [seed] (hexadecimal) to generate the messages.").hasArgs().argName("seed").optionalArg(false).numberOfArgs(1).build();
        OptionGroup ecdsaMessage = new OptionGroup();
        ecdsaMessage.addOption(file);
        ecdsaMessage.addOption(message);
        ecdsaMessage.addOption(messageSeed);

        Options testOpts = new Options();
        testOpts.addOption(bits);
        testOpts.addOption(namedCurve);
        testOpts.addOption(curveName);
        testOpts.addOption(output);
        testOpts.addOption(quiet);
        testOpts.addOption(prngSeed);
        testOpts.addOption(Option.builder("gt").longOpt("kpg-type").desc("Set the KeyPairGenerator object [type].").hasArg().argName("type").optionalArg(false).build());
        testOpts.addOption(Option.builder("kt").longOpt("ka-type").desc("Set the KeyAgreement object [type].").hasArg().argName("type").optionalArg(false).build());
        testOpts.addOption(Option.builder("st").longOpt("sig-type").desc("Set the Signature object [type].").hasArg().argName("type").optionalArg(false).build());
        testOpts.addOption(Option.builder("f").longOpt("format").desc("Set the output format, one of text,yaml,xml.").hasArg().argName("format").optionalArg(false).build());
        testOpts.addOption(Option.builder().longOpt("key-type").desc("Set the key [algorithm] for which the key should be derived in KeyAgreements with KDF. Default is \"AES\".").hasArg().argName("algorithm").optionalArg(false).build());
        List<Argument> testArgs = new LinkedList<>();
        testArgs.add(new Argument("test-suite", "The test suite to run.", true));
        ParserOptions test = new ParserOptions(new TreeParser(Collections.emptyMap(), true, testArgs), testOpts, "Test a library.");
        actions.put("test", test);

        Options ecdhOpts = new Options();
        ecdhOpts.addOption(bits);
        ecdhOpts.addOption(namedCurve);
        ecdhOpts.addOption(curveName);
        ecdhOpts.addOption(outputRaw);
        ecdhOpts.addOption(timeSource);
        ecdhOpts.addOption(prngSeed);
        ecdhOpts.addOption(Option.builder("t").longOpt("type").desc("Set KeyAgreement object [type].").hasArg().argName("type").optionalArg(false).build());
        ecdhOpts.addOption(Option.builder().longOpt("key-type").desc("Set the key [algorithm] for which the key should be derived in KeyAgreements with KDF. Default is \"AES\".").hasArg().argName("algorithm").optionalArg(false).build());
        ecdhOpts.addOption(Option.builder("n").longOpt("amount").hasArg().argName("amount").optionalArg(false).desc("Do ECDH [amount] times.").build());
        ecdhOpts.addOptionGroup(publicKey);
        ecdhOpts.addOption(Option.builder().longOpt("fixed-private").desc("Perform ECDH with fixed private key.").build());
        ecdhOpts.addOptionGroup(privateKey);
        ecdhOpts.addOption(Option.builder().longOpt("fixed-public").desc("Perform ECDH with fixed public key.").build());
        ParserOptions ecdh = new ParserOptions(new DefaultParser(), ecdhOpts, "Perform EC based KeyAgreement.");
        actions.put("ecdh", ecdh);

        Options ecdsaOpts = new Options();
        ecdsaOpts.addOption(bits);
        ecdsaOpts.addOption(namedCurve);
        ecdsaOpts.addOption(curveName);
        ecdsaOpts.addOption(outputRaw);
        ecdsaOpts.addOption(timeSource);
        ecdsaOpts.addOption(prngSeed);
        ecdsaOpts.addOptionGroup(privateKey);
        ecdsaOpts.addOptionGroup(publicKey);
        ecdsaOpts.addOption(Option.builder().longOpt("fixed").desc("Perform all ECDSA with fixed keypair.").build());
        ecdsaOpts.addOption(Option.builder("t").longOpt("type").desc("Set Signature object [type].").hasArg().argName("type").optionalArg(false).build());
        ecdsaOpts.addOption(Option.builder("n").longOpt("amount").hasArg().argName("amount").optionalArg(false).desc("Do ECDSA [amount] times.").build());
        ecdsaOpts.addOptionGroup(ecdsaMessage);
        ParserOptions ecdsa = new ParserOptions(new DefaultParser(), ecdsaOpts, "Perform EC based Signature.");
        actions.put("ecdsa", ecdsa);

        Options generateOpts = new Options();
        generateOpts.addOption(bits);
        generateOpts.addOption(namedCurve);
        generateOpts.addOption(curveName);
        generateOpts.addOption(outputRaw);
        generateOpts.addOption(timeSource);
        generateOpts.addOption(prngSeed);
        generateOpts.addOption(Option.builder("n").longOpt("amount").hasArg().argName("amount").optionalArg(false).desc("Generate [amount] of EC keys.").build());
        generateOpts.addOption(Option.builder("t").longOpt("type").hasArg().argName("type").optionalArg(false).desc("Set KeyPairGenerator object [type].").build());
        ParserOptions generate = new ParserOptions(new DefaultParser(), generateOpts, "Generate EC keypairs.");
        actions.put("generate", generate);

        Options exportOpts = new Options();
        exportOpts.addOption(bits);
        exportOpts.addOption(outputRaw);
        exportOpts.addOption(Option.builder("t").longOpt("type").hasArg().argName("type").optionalArg(false).desc("Set KeyPair object [type].").build());
        ParserOptions export = new ParserOptions(new DefaultParser(), exportOpts, "Export default curve parameters.");
        actions.put("export", export);

        Options listDataOpts = new Options();
        List<Argument> listDataArgs = new LinkedList<>();
        listDataArgs.add(new Argument("what", "what to list.", false));
        ParserOptions listData = new ParserOptions(new TreeParser(Collections.emptyMap(), false, listDataArgs), listDataOpts, "List/show contained EC domain parameters/keys.");
        actions.put("list-data", listData);

        Options listLibsOpts = new Options();
        ParserOptions listLibs = new ParserOptions(new DefaultParser(), listLibsOpts, "List supported libraries.");
        actions.put("list-libs", listLibs);

        Options listSuitesOpts = new Options();
        ParserOptions listSuites = new ParserOptions(new DefaultParser(), listSuitesOpts, "List supported test suites.");
        actions.put("list-suites", listSuites);

        Options listIdentsOpts = new Options();
        ParserOptions listIdents = new ParserOptions(new DefaultParser(), listIdentsOpts, "List KeyPairGenerator, KeyAgreement and Signature types.");
        actions.put("list-types", listIdents);

        List<Argument> baseArgs = new LinkedList<>();
        baseArgs.add(new Argument("lib", "What library to use.", false));
        optParser = new TreeParser(actions, false, baseArgs);

        opts.addOption(Option.builder("V").longOpt("version").desc("Print version info.").build());
        opts.addOption(Option.builder("h").longOpt("help").desc("Print help(about <command>).").hasArg().argName("command").optionalArg(true).build());
        opts.addOption(Option.builder("C").longOpt("color").desc("Print stuff with color, requires ANSI terminal.").build());
        opts.addOption(Option.builder().longOpt("no-preload").desc("Do not use LD_PRELOAD.").build());

        return optParser.parse(opts, args);
    }

    /**
     *
     */
    private void listLibraries() {
        for (ProviderECLibrary lib : libs) {
            if (cfg.selected == null || lib == cfg.selected) {
                try {
                    if (!lib.initialize()) {
                        continue;
                    }
                } catch (Exception ex) {
                    System.err.println("Error initializing " + lib.fullName());
                    System.err.println(ex.getMessage());
                    continue;
                }

                System.out.println("\t- " + Colors.bold(lib.name()));
                System.out.println(Colors.bold("\t\t- Fullname: ") + lib.getProvider().getName());
                System.out.println(Colors.bold("\t\t- Version: ") + lib.getProvider().getVersionStr());
                System.out.println(Colors.bold("\t\t- Supports native timing: ") + lib.getNativeTimingSupport().toString());
                System.out.println(Colors.bold("\t\t- Supports deterministic PRNG: ") + lib.supportsDeterministicPRNG());
                Set<KeyPairGeneratorIdent> kpgs = lib.getKPGs();
                if (!kpgs.isEmpty()) {
                    System.out.println(Colors.bold("\t\t- KeyPairGenerators: ") + kpgs.stream().map(KeyPairGeneratorIdent::getName).sorted().collect(Collectors.joining(", ")));
                }
                Set<KeyAgreementIdent> eckas = lib.getKAs();
                if (!eckas.isEmpty()) {
                    System.out.println(Colors.bold("\t\t- KeyAgreements: ") + eckas.stream().map(KeyAgreementIdent::getName).sorted().collect(Collectors.joining(", ")));
                }
                Set<SignatureIdent> sigs = lib.getSigs();
                if (!sigs.isEmpty()) {
                    System.out.println(Colors.bold("\t\t- Signatures: ") + sigs.stream().map(SignatureIdent::getName).sorted().collect(Collectors.joining(", ")));
                }
                Set<String> curves = lib.getCurves();
                if (!curves.isEmpty()) {
                    System.out.println(Colors.bold("\t\t- Curves: ") + curves.stream().sorted().collect(Collectors.joining(", ")));
                }
                System.out.println();
            }
        }
    }

    /**
     *
     */
    private void listSuites() {
        StandaloneTestSuite[] suites = new StandaloneTestSuite[]{
                new StandaloneDefaultSuite(null, null, null),
                new StandaloneTestVectorSuite(null, null, null),
                new StandaloneInvalidSuite(null, null, null),
                new StandaloneWrongSuite(null, null, null),
                new StandaloneDegenerateSuite(null, null, null),
                new StandaloneCofactorSuite(null, null, null),
                new StandaloneEdgeCasesSuite(null, null, null),
                new StandaloneSignatureSuite(null, null, null),
                new StandaloneCompositeSuite(null, null, null),
                new StandaloneTwistSuite(null, null, null),
                new StandaloneMiscSuite(null, null, null),
                new StandalonePerformanceSuite(null, null, null)};
        for (StandaloneTestSuite suite : suites) {
            System.out.println(" - " + suite.getName());
            for (String line : suite.getDescription()) {
                System.out.println("\t" + line);
            }
        }
    }

    /**
     *
     */
    private void listIdents() {
        System.out.println(Colors.bold("\t- KeyPairGenerator"));
        for (KeyPairGeneratorIdent kpgIdent : KeyPairGeneratorIdent.list()) {
            System.out.println("\t\t- " + Colors.underline(kpgIdent.getName()) + " " + kpgIdent);
        }
        System.out.println(Colors.bold("\t- KeyAgreement"));
        for (KeyAgreementIdent kaIdent : KeyAgreementIdent.list()) {
            System.out.println("\t\t- " + Colors.underline(kaIdent.getName()) + " " + kaIdent);
        }
        System.out.println(Colors.bold("\t- Signature"));
        for (SignatureIdent sigIdent : SignatureIdent.list()) {
            System.out.println("\t\t- " + Colors.underline(sigIdent.getName()) + " " + sigIdent);
        }
    }

    /**
     *
     */
    private void ecdh() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
        ProviderECLibrary lib = cfg.selected;

        String algo = cli.getOptionValue("ecdh.type", "ECDH");
        String keyAlgo = cli.getOptionValue("ecdh.key-type", "AES");
        KeyAgreementIdent kaIdent = lib.getKAs().stream()
                .filter((ident) -> ident.contains(algo))
                .findFirst()
                .orElse(null);

        String baseAlgo;
        if (algo.contains("with")) {
            baseAlgo = algo.split("with")[0];
        } else {
            baseAlgo = algo;
        }

        KeyPairGeneratorIdent kpIdent = lib.getKPGs().stream()
                .filter((ident) -> ident.contains(algo))
                .findFirst()
                .orElse(lib.getKPGs().stream()
                        .filter((ident) -> ident.contains(baseAlgo))
                        .findFirst()
                        .orElse(lib.getKPGs().stream()
                                .filter((ident) -> ident.contains("ECDH"))
                                .findFirst()
                                .orElse(lib.getKPGs().stream()
                                        .filter((ident) -> ident.contains("EC"))
                                        .findFirst()
                                        .orElse(null))));

        if (kaIdent == null || kpIdent == null) {
            throw new NoSuchAlgorithmException(algo);
        }

        SecureRandom random;
        if (cli.hasOption("ecdh.prng-seed")) {
            String seedString = cli.getOptionValue("ecdh.prng-seed");
            byte[] seed = ByteUtil.hexToBytes(seedString, true);
            random = Util.getRandom(seed);
            if (!lib.setupDeterministicPRNG(seed)) {
                System.err.println("Couldn't set PRNG seed.");
                return;
            }
        } else {
            random = new SecureRandom();
        }

        KeyAgreement ka = kaIdent.getInstance(lib.getProvider());
        KeyPairGenerator kpg = kpIdent.getInstance(lib.getProvider());
        AlgorithmParameterSpec spec = null;
        if (cli.hasOption("ecdh.bits")) {
            int bits = Integer.parseInt(cli.getOptionValue("ecdh.bits"));
            kpg.initialize(bits, random);
        } else if (cli.hasOption("ecdh.named-curve")) {
            String curveName = cli.getOptionValue("ecdh.named-curve");
            EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, curveName);
            if (curve == null) {
                System.err.println("Curve not found: " + curveName);
                return;
            }
            spec = curve.toSpec();
            kpg.initialize(spec, random);
        } else if (cli.hasOption("ecdh.curve-name")) {
            String curveName = cli.getOptionValue("ecdh.curve-name");
            spec = new ECGenParameterSpec(curveName);
            kpg.initialize(spec, random);
        } else if (cli.hasOption("ecdh.prng-seed") && !(lib instanceof NativeECLibrary)) {
            // TODO: This only happens if at least one of the (pubkey and privkey) needs to be generated.
            System.err.println("Unable to pass PRNG seed to a non-native library without specifying either key-size, named curve or curve name options.");
            return;
        }

        if (cli.hasOption("ecdh.time-source")) {
            if (!lib.setNativeTimingType(cli.getOptionValue("ecdh.time-source"))) {
                System.err.println("Couldn't set native time source.");
                return;
            }
        }

        PrintStream out;
        if (cli.hasOption("ecdh.output")) {
            out = new PrintStream(FileUtil.openStream(cli.getOptionValues("ecdh.output")));
        } else {
            out = System.out;
        }

        String timeUnit = "nano";
        if (!lib.getNativeTimingSupport().isEmpty()) {
            timeUnit = lib.getNativeTimingUnit();
        }

        String hashAlgo = kaIdent.getBaseAlgo() != null ? String.format("[%s]", kaIdent.getBaseAlgo()) : "[NONE]";
        out.printf("index;time[%s];pubW;privS;secret%s%n", timeUnit, hashAlgo);

        KeyPair one = null;
        if (cli.hasOption("ecdh.fixed-private") && !cli.hasOption("ecdh.named-private") && !cli.hasOption("ecdh.private")) {
            one = kpg.genKeyPair();
        }
        KeyPair other = null;
        if (cli.hasOption("ecdh.fixed-public") && !cli.hasOption("ecdh.named-public") && !cli.hasOption("ecdh.public")) {
            other = kpg.genKeyPair();
        }

        PrivateKey privkey = (ECPrivateKey) ECUtil.loadKey(EC_Consts.PARAMETER_S, cli.getOptionValue("ecdh.named-private"), cli.getOptionValue("ecdh.private"), spec);
        PublicKey pubkey = (ECPublicKey) ECUtil.loadKey(EC_Consts.PARAMETER_W, cli.getOptionValue("ecdh.named-public"), cli.getOptionValue("ecdh.public"), spec);

        int amount = Integer.parseInt(cli.getOptionValue("ecdh.amount", "1"));
        for (int i = 0; i < amount || amount == 0; ++i) {
            if (!cli.hasOption("ecdh.fixed-private") && !cli.hasOption("ecdh.named-private") && !cli.hasOption("ecdh.private")) {
                one = kpg.genKeyPair();
            }
            if (!cli.hasOption("ecdh.fixed-public") && !cli.hasOption("ecdh.named-public") && !cli.hasOption("ecdh.public")) {
                other = kpg.genKeyPair();
            }

            if (!cli.hasOption("ecdh.named-private") && !cli.hasOption("ecdh.private")) {
                privkey = one.getPrivate();
            }

            if (!cli.hasOption("ecdh.named-public") && !cli.hasOption("ecdh.public")) {
                pubkey = other.getPublic();
            }

            long elapsed = -System.nanoTime();
            if (spec instanceof ECParameterSpec && lib instanceof NativeECLibrary) {
                ka.init(privkey, spec, random);
            } else {
                ka.init(privkey, random);
            }
            ka.doPhase(pubkey, true);
            elapsed += System.nanoTime();
            SecretKey derived;
            byte[] result;
            elapsed -= System.nanoTime();
            if (kaIdent.requiresKeyAlgo()) {
                derived = ka.generateSecret(keyAlgo);
                result = derived.getEncoded();
            } else {
                result = ka.generateSecret();
            }
            elapsed += System.nanoTime();
            if (!lib.getNativeTimingSupport().isEmpty()) {
                elapsed = lib.getLastNativeTiming();
            }
            ka = kaIdent.getInstance(lib.getProvider());

            String pub = ByteUtil.bytesToHex(ECUtil.pubkeyToBytes(pubkey), false);
            String priv = ByteUtil.bytesToHex(ECUtil.privkeyToBytes(privkey), false);
            String dh = ByteUtil.bytesToHex(result, false);
            out.printf("%d;%d;%s;%s;%s%n", i, elapsed, pub, priv, dh);
        }

        if (cli.hasOption("ecdh.output")) {
            out.close();
        }
    }

    /**
     *
     */
    private void ecdsa() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, SignatureException {
        ProviderECLibrary lib = cfg.selected;

        SecureRandom random;
        if (cli.hasOption("ecdsa.prng-seed")) {
            String seedString = cli.getOptionValue("ecdsa.prng-seed");
            byte[] seed = ByteUtil.hexToBytes(seedString, true);
            random = Util.getRandom(seed);
            if (!lib.setupDeterministicPRNG(seed)) {
                System.err.println("Couldn't set PRNG seed.");
                return;
            }
        } else {
            random = new SecureRandom();
        }

        byte[] data = null;
        String dataString = null;
        SecureRandom dataRandom = null;
        if (cli.hasOption("ecdsa.file")) {
            String fileName = cli.getOptionValue("ecdsa.file");
            File in = new File(fileName);
            long len = in.length();
            if (len == 0) {
                throw new FileNotFoundException(fileName);
            }
            data = Files.readAllBytes(in.toPath());
            dataString = "";
        } else if (cli.hasOption("ecdsa.data")) {
            dataString = cli.getOptionValue("ecdsa.data");
            data = ByteUtil.hexToBytes(dataString);
        } else if (cli.hasOption("ecdsa.data-seed")) {
            String seedString = cli.getOptionValue("ecdsa.prng-seed");
            byte[] seed = ByteUtil.hexToBytes(seedString, true);
            dataRandom = Util.getRandom(seed);
        } else {
            dataRandom = new SecureRandom();
        }

        String algo = cli.getOptionValue("ecdsa.type", "ECDSA");
        SignatureIdent sigIdent = lib.getSigs().stream()
                .filter((ident) -> ident.contains(algo))
                .findFirst()
                .orElse(null);

        String baseAlgo;
        if (algo.contains("with")) {
            baseAlgo = algo.split("with")[1];
        } else {
            baseAlgo = algo;
        }
        KeyPairGeneratorIdent kpIdent = lib.getKPGs().stream()
                .filter((ident) -> ident.contains(algo))
                .findFirst()
                .orElse(lib.getKPGs().stream()
                        .filter((ident) -> ident.contains(baseAlgo))
                        .findFirst()
                        .orElse(lib.getKPGs().stream()
                                .filter((ident) -> ident.contains("ECDSA"))
                                .findFirst()
                                .orElse(lib.getKPGs().stream()
                                        .filter((ident) -> ident.contains("EC"))
                                        .findFirst()
                                        .orElse(null))));

        if (sigIdent == null || kpIdent == null) {
            throw new NoSuchAlgorithmException(algo);
        }
        Signature sig = sigIdent.getInstance(lib.getProvider());
        KeyPairGenerator kpg = kpIdent.getInstance(lib.getProvider());
        ECParameterSpec spec = null;
        if (cli.hasOption("ecdsa.bits")) {
            int bits = Integer.parseInt(cli.getOptionValue("ecdsa.bits"));
            kpg.initialize(bits, random);
        } else if (cli.hasOption("ecdsa.named-curve")) {
            String curveName = cli.getOptionValue("ecdsa.named-curve");
            EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, curveName);
            if (curve == null) {
                System.err.println("Curve not found: " + curveName);
                return;
            }
            spec = curve.toSpec();
            kpg.initialize(spec, random);
        } else if (cli.hasOption("ecdsa.curve-name")) {
            String curveName = cli.getOptionValue("ecdsa.curve-name");
            kpg.initialize(new ECGenParameterSpec(curveName), random);
        } else if (cli.hasOption("ecdsa.prng-seed") && !(lib instanceof NativeECLibrary)) {
            // TODO: This only happens if at least one of the (pubkey and privkey) needs to be generated.
            System.err.println("Unable to pass PRNG seed to a non-native library without specifying either key-size, named curve or curve name options.");
            return;
        }

        if (cli.hasOption("ecdsa.time-source")) {
            if (!lib.setNativeTimingType(cli.getOptionValue("ecdsa.time-source"))) {
                System.err.println("Couldn't set native time source.");
                return;
            }
        }

        PrintStream out;
        if (cli.hasOption("ecdsa.output")) {
            out = new PrintStream(FileUtil.openStream(cli.getOptionValues("ecdsa.output")));
        } else {
            out = System.out;
        }

        String timeUnit = "nano";
        if (!lib.getNativeTimingSupport().isEmpty()) {
            timeUnit = lib.getNativeTimingUnit();
        }

        String hashAlgoOut = sigIdent.getHashAlgo() != null ? String.format("[%s]", sigIdent.getHashAlgo()) : "";
        out.printf("index;signTime[%s];verifyTime[%s];data;pubW;privS;signature%s;nonce;verified%n", timeUnit, timeUnit, hashAlgoOut);

        PrivateKey privkey = (ECPrivateKey) ECUtil.loadKey(EC_Consts.PARAMETER_S, cli.getOptionValue("ecdsa.named-private"), cli.getOptionValue("ecdsa.private"), spec);
        PublicKey pubkey = (ECPublicKey) ECUtil.loadKey(EC_Consts.PARAMETER_W, cli.getOptionValue("ecdsa.named-public"), cli.getOptionValue("ecdsa.public"), spec);

        KeyPair one;
        if (cli.hasOption("ecdsa.fixed")) {
            one = kpg.genKeyPair();
            if (!cli.hasOption("ecdsa.named-private")) {
                privkey = one.getPrivate();
            }
            if (!cli.hasOption("ecdsa.named-public")) {
                pubkey = one.getPublic();
            }
        }


        int amount = Integer.parseInt(cli.getOptionValue("ecdsa.amount", "1"));
        for (int i = 0; i < amount || amount == 0; ++i) {
            if ((!cli.hasOption("ecdsa.named-private") || !cli.hasOption("ecdsa.named-public")) && !cli.hasOption("ecdsa.fixed")) {
                one = kpg.genKeyPair();

                if (!cli.hasOption("ecdsa.named-private")) {
                    privkey = one.getPrivate();
                }
                if (!cli.hasOption("ecdsa.named-public")) {
                    pubkey = one.getPublic();
                }
            }

            if (dataRandom != null) {
                data = dataRandom.generateSeed(16);
                dataString = ByteUtil.bytesToHex(data, false);
            }

            sig.initSign(privkey, random);
            sig.update(data);

            long signTime = -System.nanoTime();
            byte[] signature = sig.sign();
            signTime += System.nanoTime();
            if (!lib.getNativeTimingSupport().isEmpty()) {
                signTime = lib.getLastNativeTiming();
            }

            sig.initVerify(pubkey);
            sig.update(data);

            long verifyTime = -System.nanoTime();
            boolean verified = sig.verify(signature);
            verifyTime += System.nanoTime();
            if (!lib.getNativeTimingSupport().isEmpty()) {
                verifyTime = lib.getLastNativeTiming();
            }

            String pub = ByteUtil.bytesToHex(ECUtil.pubkeyToBytes(pubkey), false);
            String priv = ByteUtil.bytesToHex(ECUtil.privkeyToBytes(privkey), false);
            String sign = ByteUtil.bytesToHex(signature, false);
            String k = "";
            if (privkey instanceof ECPrivateKey) {
                ECPrivateKey ecPrivateKey = (ECPrivateKey) privkey;
                ECParameterSpec kSpec = spec;
                if (kSpec == null) {
                    kSpec = ecPrivateKey.getParams();
                }
                if (kSpec != null) {
                    // Parse the types out of SignatureIdent.
                    String hashAlgo = sigIdent.getHashAlgo();
                    String sigType = sigIdent.getSigType();
                    if (sigType == null) {
                        sigType = sigIdent.toString();
                    }

                    BigInteger kValue = ECUtil.recoverSignatureNonce(signature, data, ecPrivateKey.getS(), kSpec, hashAlgo, sigType);
                    if (kValue != null) {
                        k = ByteUtil.bytesToHex(kValue.toByteArray(), false);
                    }
                }
            }

            out.printf("%d;%d;%d;%s;%s;%s;%s;%s;%d%n", i, signTime, verifyTime, dataString, pub, priv, sign, k, verified ? 1 : 0);
        }

        if (cli.hasOption("ecdsa.output")) {
            out.close();
        }
    }

    /**
     *
     */
    private void generate() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, FileNotFoundException {
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
        }

        SecureRandom random;
        if (cli.hasOption("generate.prng-seed")) {
            String seedString = cli.getOptionValue("generate.prng-seed");
            byte[] seed = ByteUtil.hexToBytes(seedString, true);
            random = Util.getRandom(seed);
            if (!lib.setupDeterministicPRNG(seed)) {
                System.err.println("Couldn't set PRNG seed.");
                return;
            }
        } else {
            random = new SecureRandom();
        }

        KeyPairGenerator kpg = ident.getInstance(lib.getProvider());
        if (cli.hasOption("generate.bits")) {
            int bits = Integer.parseInt(cli.getOptionValue("generate.bits"));
            kpg.initialize(bits, random);
        } else if (cli.hasOption("generate.named-curve")) {
            String curveName = cli.getOptionValue("generate.named-curve");
            EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, curveName);
            if (curve == null) {
                System.err.println("Curve not found: " + curveName);
                return;
            }
            kpg.initialize(curve.toSpec(), random);
        } else if (cli.hasOption("generate.curve-name")) {
            String curveName = cli.getOptionValue("generate.curve-name");
            kpg.initialize(new ECGenParameterSpec(curveName), random);
        } else if (cli.hasOption("generate.prng-seed") && !(lib instanceof NativeECLibrary)) {
            System.err.println("Unable to pass PRNG seed to a non-native library without specifying either key-size, named curve or curve name options.");
            return;
        }

        if (cli.hasOption("generate.time-source")) {
            if (!lib.setNativeTimingType(cli.getOptionValue("generate.time-source"))) {
                System.err.println("Couldn't set native time source.");
                return;
            }
        }

        String timeUnit = "nano";
        if (!lib.getNativeTimingSupport().isEmpty()) {
            timeUnit = lib.getNativeTimingUnit();
        }

        PrintStream out;
        if (cli.hasOption("generate.output")) {
            out = new PrintStream(FileUtil.openStream(cli.getOptionValues("generate.output")));
        } else {
            out = System.out;
        }

        out.printf("index;time[%s];pubW;privS%n", timeUnit);

        int amount = Integer.parseInt(cli.getOptionValue("generate.amount", "1"));
        for (int i = 0; i < amount || amount == 0; ++i) {
            long elapsed = -System.nanoTime();
            KeyPair kp;
            try {
                kp = kpg.genKeyPair();
            } catch (SignalException exc) {
                System.err.println(exc.getSigInfo());
                continue;
            } catch (TimeoutException exc) {
                System.err.println(exc);
                continue;
            }
            elapsed += System.nanoTime();
            if (!lib.getNativeTimingSupport().isEmpty()) {
                elapsed = lib.getLastNativeTiming();
            }
            PublicKey pubkey = kp.getPublic();
            PrivateKey privkey = kp.getPrivate();
            byte[] pubBytes = ECUtil.pubkeyToBytes(pubkey);
            byte[] privBytes = ECUtil.privkeyToBytes(privkey);
            String pub = ByteUtil.bytesToHex(pubBytes, false);
            String priv = ByteUtil.bytesToHex(privBytes, false);
            if (pubBytes == null || privBytes == null) {
                System.err.println(pubkey.getClass().getCanonicalName());
                System.err.println(privkey.getClass().getCanonicalName());
                break;
            }
            out.printf("%d;%d;%s;%s%n", i, elapsed, pub, priv);
        }

        if (cli.hasOption("generate.output")) {
            out.close();
        }
    }

    /**
     *
     */
    private void test() throws TestException, ParserConfigurationException, FileNotFoundException {
        TestWriter writer = new FileTestWriter(cli.getOptionValue("test.format", "text"), !cli.hasOption("test.quiet"), cli.getOptionValues("test.output"));
        StandaloneTestSuite suite;
        String suiteOpt = cli.getArg(0) != null ? cli.getArg(0).toLowerCase() : "default";
        String testSuite;
        int testFrom;
        int testTo;
        if (suiteOpt.contains(":")) {
            String[] parts = suiteOpt.split(":");
            if (parts.length < 2 || parts.length > 3) {
                System.err.println("Invalid test suite selection.");
                return;
            }
            testSuite = parts[0];
            try {
                testFrom = Integer.parseInt(parts[1]);
            } catch (NumberFormatException nfe) {
                System.err.println("Invalid test_from number: " + parts[1] + ".");
                return;
            }
            if (parts.length == 3) {
                try {
                    testTo = Integer.parseInt(parts[2]);
                } catch (NumberFormatException nfe) {
                    System.err.println("Invalid test_to number: " + parts[2] + ".");
                    return;
                }
            } else {
                testTo = -1;
            }
        } else {
            testSuite = suiteOpt;
            testFrom = 0;
            testTo = -1;
        }

        ProviderECLibrary lib = cfg.selected;
        if (cli.hasOption("test.prng-seed")) {
            String seedString = cli.getOptionValue("test.prng-seed");
            byte[] seed = ByteUtil.hexToBytes(seedString, true);
            if (!lib.setupDeterministicPRNG(seed)) {
                System.err.println("Couldn't set PRNG seed.");
                return;
            }
        }

        switch (testSuite) {
            case "test-vectors":
                suite = new StandaloneTestVectorSuite(writer, cfg, cli);
                break;
            case "wrong":
                suite = new StandaloneWrongSuite(writer, cfg, cli);
                break;
            case "degenerate":
                suite = new StandaloneDegenerateSuite(writer, cfg, cli);
                break;
            case "cofactor":
                suite = new StandaloneCofactorSuite(writer, cfg, cli);
                break;
            case "composite":
                suite = new StandaloneCompositeSuite(writer, cfg, cli);
                break;
            case "invalid":
                suite = new StandaloneInvalidSuite(writer, cfg, cli);
                break;
            case "edge-cases":
                suite = new StandaloneEdgeCasesSuite(writer, cfg, cli);
                break;
            case "signature":
                suite = new StandaloneSignatureSuite(writer, cfg, cli);
                break;
            case "twist":
                suite = new StandaloneTwistSuite(writer, cfg, cli);
                break;
            case "miscellaneous":
                suite = new StandaloneMiscSuite(writer, cfg, cli);
                break;
            case "performance":
                suite = new StandalonePerformanceSuite(writer, cfg, cli);
                break;
            default:
                suite = new StandaloneDefaultSuite(writer, cfg, cli);
                break;
        }

        suite.run(testFrom, testTo);
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
        }
        KeyPairGenerator kpg = ident.getInstance(lib.getProvider());
        if (cli.hasOption("export.bits")) {
            int bits = Integer.parseInt(cli.getOptionValue("export.bits"));
            kpg.initialize(bits);
        }
        KeyPair kp = kpg.genKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();
        ECParameterSpec params = privateKey.getParams();
        if (params == null) {
            System.err.println("Parameters could not be exported (they are NULL).");
        } else {
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
        private final ProviderECLibrary[] libs;
        public ProviderECLibrary selected = null;
        public boolean color = false;

        public Config(ProviderECLibrary[] libs) {
            this.libs = libs;
        }

        boolean readOptions(TreeCommandLine cli) {
            color = cli.hasOption("color");
            Colors.enabled = color;

            String next = cli.getNextName();

            if (cli.isNext("generate") || cli.isNext("export") || cli.isNext("ecdh") || cli.isNext("ecdsa") || cli.isNext("test")) {
                if (!cli.hasArg(-1)) {
                    System.err.println("Missing library name argument.");
                    return false;
                }

                boolean hasBits = cli.hasOption(next + ".bits");
                boolean hasNamedCurve = cli.hasOption(next + ".named-curve");
                boolean hasCurveName = cli.hasOption(next + ".curve-name");
                if (hasBits ^ hasNamedCurve ? hasCurveName : hasBits) {
                    System.err.println("You can only specify bitsize or a named curve/curve name, nor both.");
                    return false;
                }

                if (hasCurveName && (cli.hasOption(next + ".named-public") || cli.hasOption(next + ".named-private") || cli.hasOption(next + ".public") || cli.hasOption(next + ".private"))) {
                    System.err.println("Cannot specify key with a curve name switch, needs explicit parameteres.");
                    return false;
                }
            }

            if (!cli.isNext("list-data") && !cli.isNext("list-suites") && !cli.isNext("list-types")) {
                String libraryName = cli.getArg(-1);
                if (libraryName != null) {
                    List<ProviderECLibrary> matchedLibs = new LinkedList<>();
                    for (ProviderECLibrary lib : libs) {
                        if (lib.name().toLowerCase().contains(libraryName.toLowerCase())) {
                            matchedLibs.add(lib);
                        }
                    }
                    if (matchedLibs.isEmpty()) {
                        System.err.println("No library " + libraryName + " found.");
                        return false;
                    } else if (matchedLibs.size() > 1) {
                        System.err.println("Multiple matching libraries found: " + matchedLibs.stream().map(ECLibrary::name).collect(Collectors.joining(",")));
                        return false;
                    } else {
                        selected = matchedLibs.get(0);
                        try {
                            selected.initialize();
                        } catch (Exception ex) {
                            System.err.println("Error initializing " + selected.fullName());
                            System.err.println(ex.getMessage());
                        }
                    }
                }
            }

            if (cli.hasOption("test.format")) {
                String fmt = cli.getOptionValue("test.format");
                String[] formats = new String[]{"text", "xml", "yaml", "yml"};
                if (!Arrays.asList(formats).contains(fmt.toLowerCase())) {
                    System.err.println("Invalid format specified.");
                    return false;
                }
            }

            if (cli.isNext("ecdh")) {
                if ((cli.hasOption("ecdh.public") || cli.hasOption("ecdh.private")) && !cli.hasOption("ecdh.named-curve")) {
                    System.err.println("Need to specify a named curve when specifying public/private key in file.");
                    return false;
                }
            }

            if (cli.isNext("ecdsa")) {
                if ((cli.hasOption("ecdsa.public") || cli.hasOption("ecdsa.private")) && !cli.hasOption("ecdsa.named-curve")) {
                    System.err.println("Need to specify a named curve when specifying public/private key in file.");
                    return false;
                }
            }

            if (cli.isNext("generate") || cli.isNext("ecdh") || cli.isNext("ecdsa")) {
                if (cli.hasOption(next + ".time-source")) {
                    String source = cli.getOptionValue(next + ".time-source");
                    if (!selected.getNativeTimingSupport().contains(source)) {
                        System.err.printf("Time source %s unavailable for library %s.%n", source, selected.name());
                        return false;
                    }
                }
            }

            if (cli.isNext("generate") || cli.isNext("ecdh") || cli.isNext("ecdsa") || cli.isNext("test")) {
                if (cli.hasOption(next + ".prng-seed")) {
                    if (!selected.supportsDeterministicPRNG()) {
                        System.err.printf("Deterministic PRNG is not supported by library %s.%n", selected.name());
                        return false;
                    }
                }
            }

            return true;
        }
    }
}
