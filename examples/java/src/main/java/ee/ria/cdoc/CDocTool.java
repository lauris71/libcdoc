// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

package ee.ria.cdoc;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class CDocTool {
    private enum Action {
        INVALID,
        ENCRYPT,
        DECRYPT,
        LOCKS
    }

    private static final HexFormat hex = HexFormat.of();

    public static String getArg(int arg_idx, String[] args) {
        arg_idx += 1;
        if (arg_idx >= args.length) {
            failUsage("Missing argument");
        }
        return args[arg_idx];
    }

    // Make logger static to ensure that it is not garbage-collected as long as it is attached to library
    private static Logger logger;

    private static void printUsage(PrintStream ofs) {
        ofs.print("""
    Usage:
        CDocTool [--library JNI_LIBRARY] ACTION ARGUMENTS FILE(S)

        --library before ACTION is the path to the libcdoc JNI library.
        Everywhere else --library refers to the PKCS#11 module.

        Actions:
            encrypt     Encrypt files
            decrypt     Decrypt files
            locks       List locks in a CDoc file

        Encryption arguments:
            --rcpt RECIPIENT        Recipient info, where recipient is one of the following:
                <label>:cert:CERTIFICATE_FILE             - public key from certificate file (DER format).
                <label>:pkey:HEX_KEY                      - hex encoded public key (DER format; rsa, secp384r1, secp256r1 or secp521r1 key).
                <label>:pfkey:FILENAME                    - public key from file (DER format; rsa, secp384r1, secp256r1 or secp521r1 key).
                <label>:skey:HEX_KEY                      - AES key, hex encoded.
                <label>:pw:PASS                           - AES key derived from password with PWBKDF.
                <label>:p11sk:SLOT[:PIN][:KEY_ID][:LABEL] - use AES key from PKCS11 module.
                <label>:p11pk:SLOT[:PIN][:KEY_ID][:LABEL] - use public key from PKCS11 module.
            --v1                      - creates CDOC1 version container. Supported only for encryption with certificate.
        Decryption arguments:
            --label LABEL          Lock label
            --lock-idx INDEX       Lock number (1-based)
            --cert FILE            Certificate file; the matching lock is located by certificate
            --password PASSWORD    Lock's password (or PKCS11 PIN)
            --pin PIN              PKCS11 PIN
            --secret HEX           Symmetric (AES) key, hex encoded
            --pkey HEX             Hex encoded private key (DER format; PKCS#8 or SEC1)
            --pfkey FILE           Private key from file (DER format; PKCS#8 or SEC1)
            --slot SLOT            PKCS11 slot number
            --key-id HEX           PKCS11 key ID
            --key-label LABEL      PKCS11 key label
        Common arguments:
            --library <lib>      PKCS#11 library path
            --out <file>         Output file
            --v1                 Use CDoc version 1
            --log-level <level>  Log level (FATAL, ERROR, WARNING, INFO, DEBUG, TRACE)
        """);
    }

    private static void failUsage(String error) {
        System.err.println(error);
        printUsage(System.err);
        System.exit(1);
    }

    public static final class RcptInfo {
        public enum Type {
            LOCK,
            PASSWORD,
            PKEY,
            SKEY,
            P11_SYMMETRIC,
            P11_PKI,
            CERT,
        }
        public static final class P11Info {
            public int slot = -1;
            public byte[] key_id = null;
            public String key_label = null;
        }
        public Type type = Type.LOCK;
        public String label;
        public byte[] cert;
        public byte[] secret;
        public String id;
        public String file;
        public int lock_idx = -1;
        public P11Info p11;

        public boolean isPKCS11() { return (p11 != null) && (p11.slot >= 0); }
    }

    // Encryption state (recipient list for encryption)
    private static final ArrayList<RcptInfo> recipients = new ArrayList<>();
    private static boolean p11_library_required = false;

    // Common state
    private static String jni_library = null;
    private static LogLevel log_level = LogLevel.LEVEL_WARNING;
    private static int version = 2;
    private static String out = null;
    private static String p11_library = null;

    // Decryption state (the "key data", mirroring cdoc-tool's LockData).
    // All decryption arguments are collected here, including the PKCS11
    // parameters (slot, pin in secret, key-id, key-label).
    private static final RcptInfo key = new RcptInfo();

    private static void ensureP11(RcptInfo rcpt) {
        if (rcpt.p11 == null) rcpt.p11 = new RcptInfo.P11Info();
    }

    private static int parseSlot(String str) {
        try {
            if (str.startsWith("0x")) {
                return Integer.parseInt(str.substring(2), 16);
            }
            return Integer.parseInt(str);
        } catch (NumberFormatException e) {
            failUsage("Slot is not a number: " + str);
            return -1;
        }
    }

    private static int parseRcpt(int arg_idx, String[] args) {
        if (!args[arg_idx].equals("--rcpt")) return 0;
        String rcpt_str = getArg(arg_idx, args);
        try {
            File file;

            String[] parts = rcpt_str.split(":");
            if (parts.length < 3) {
                failUsage("Invalid recipient format: " + rcpt_str);
            }
            RcptInfo rcpt = new RcptInfo();
            rcpt.label = parts[0];
            rcpt.lock_idx = recipients.size();
            switch(parts[1]) {
                case "cert":
                    rcpt.type = RcptInfo.Type.CERT;
                    rcpt.cert = Files.readAllBytes(Paths.get(parts[2]));
                    file = new File(parts[2]);
                    rcpt.file = file.getName();
                    break;
                case "pkey":
                    if (parts.length != 3) failUsage("pkey format: label:pkey:HEX");
                    rcpt.type = RcptInfo.Type.PKEY;
                    rcpt.secret = hex.parseHex(parts[2]);
                    break;
                case "pfkey":
                    if (parts.length != 3) failUsage("pfkey format: label:pfkey:FILENAME");
                    rcpt.type = RcptInfo.Type.PKEY;
                    rcpt.secret = Files.readAllBytes(Paths.get(parts[2]));
                    file = new File(parts[2]);
                    rcpt.file = file.getName();
                    break;
                case "skey":
                    if (parts.length != 3) failUsage("skey format: label:skey:HEX_KEY");
                    rcpt.type = RcptInfo.Type.SKEY;
                    rcpt.secret = hex.parseHex(parts[2]);
                    break;
                case "pw":
                    rcpt.type = RcptInfo.Type.PASSWORD;
                    rcpt.secret = parts[2].getBytes();
                    break;
                case "p11pk":
                case "p11sk":
                    p11_library_required = true;
                    rcpt.type = (parts[1].equals("p11sk")) ? RcptInfo.Type.P11_SYMMETRIC : RcptInfo.Type.P11_PKI;
                    ensureP11(rcpt);
                    rcpt.p11.slot = parseSlot(parts[2]);
                    if (parts.length > 3) {
                        // PIN (as raw string, not hex)
                        rcpt.secret = parts[3].getBytes();
                    }
                    if (parts.length > 4) {
                        rcpt.p11.key_id = parts[4].isEmpty() ? null : hex.parseHex(parts[4]);
                    }
                    if (parts.length > 5) {
                        rcpt.p11.key_label = parts[5];
                    }
                    break;
                default:
                    failUsage("Unsupported recipient type: " + parts[1]);
            }
            recipients.add(rcpt);
            return 2;
        } catch (Exception e) {
            failUsage(String.format("Error parsing recipient %s: %s", rcpt_str, e.getMessage()));
        }
        return 0;
    }

    private static int parseCommon(int arg_idx, String[] args) {
        if (args[arg_idx].equals("--library")) {
            p11_library = getArg(arg_idx, args);
            return 2;
        } else if (args[arg_idx].equals("--log-level")) {
            String level_str = getArg(arg_idx, args);
            try {
                log_level = LogLevel.valueOf("LEVEL_" + level_str);
            } catch (IllegalArgumentException e) {
                failUsage("Invalid log level: " + level_str);
            }
            return 2;
        } else if (args[arg_idx].equals("--out")) {
            out = getArg(arg_idx, args);
            return 2;
        } else if (args[arg_idx].equals("--v1")) {
            version = 1;
            return 1;
        }
        return 0;
    }

    // Parse decryption arguments into the key RcptInfo (mirrors parse_key_data
    // in cdoc-tool.cpp). Returns the number of arguments consumed.
    private static int parseKeyData(int arg_idx, String[] args) {
        try {
            switch (args[arg_idx]) {
                case "--label":
                    key.label = getArg(arg_idx, args);
                    return 2;
                case "--lock-idx":
                    try {
                        key.lock_idx = Integer.parseInt(getArg(arg_idx, args)) - 1;
                    } catch (NumberFormatException e) {
                        failUsage("Invalid lock index");
                    }
                    if (key.lock_idx < 0) failUsage("Lock indices start from 1");
                    return 2;
                case "--cert":
                    key.cert = Files.readAllBytes(Paths.get(getArg(arg_idx, args)));
                    return 2;
                case "--password":
                case "--pin":
                    key.secret = getArg(arg_idx, args).getBytes();
                    return 2;
                case "--secret":
                    key.secret = hex.parseHex(getArg(arg_idx, args));
                    return 2;
                case "--pkey":
                    key.secret = hex.parseHex(getArg(arg_idx, args));
                    return 2;
                case "--pfkey":
                    key.secret = Files.readAllBytes(Paths.get(getArg(arg_idx, args)));
                    return 2;
                case "--slot":
                    ensureP11(key);
                    key.p11.slot = parseSlot(getArg(arg_idx, args));
                    return 2;
                case "--key-id":
                    ensureP11(key);
                    key.p11.key_id = hex.parseHex(getArg(arg_idx, args));
                    return 2;
                case "--key-label":
                    ensureP11(key);
                    key.p11.key_label = getArg(arg_idx, args);
                    return 2;
                default:
                    return 0;
            }
        } catch (IOException e) {
            failUsage("IO Exception: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            failUsage("Invalid hex value for " + args[arg_idx] + ": " + e.getMessage());
        }
        return 0;
    }

    public static void main(String[] args) {
        System.out.println("Java CDocTool");
        if (args.length == 0) {
            failUsage("No action specified");
        }

        int arg_idx = 0;
        if (args[arg_idx].equals("--library")) {
            jni_library = getArg(arg_idx, args);
            arg_idx += 2;
        }
        if (arg_idx >= args.length) {
            failUsage("No action specified");
        }

        Action action = Action.INVALID;
        switch (args[arg_idx]) {
            case "encrypt":
                action = Action.ENCRYPT;
                break;
            case "decrypt":
                action = Action.DECRYPT;
                break;
            case "locks":
                action = Action.LOCKS;
                break;
            default:
                failUsage("Invalid action: " + args[arg_idx]);
        }

        loadLibrary(jni_library);

        ArrayList<String> files = new ArrayList<>();
        int i = arg_idx + 1;
        while (i < args.length) {
            int n_args = parseCommon(i, args);
            if (n_args == 0) {
                n_args = parseKeyData(i, args);
            }
            if (n_args == 0) {
                n_args = parseRcpt(i, args);
            }
            if (n_args > 0) {
                i += n_args;
                continue;
            }
            if (!args[i].startsWith("--")) {
                files.add(args[i]);
                i += 1;
            } else {
                failUsage("Unknown argument: " + args[i]);
            }
        }

        logger = new JavaLogger();
        logger.setMinLogLevel(log_level);
        CDoc.setLogger(logger);
        CDoc.log(LogLevel.LEVEL_DEBUG, "CDocTool", 0, "Starting CDocTool.java");

        switch (action) {
            case ENCRYPT:
                if (files.isEmpty()) failUsage("No files specified");
                if (recipients.isEmpty()) failUsage("No recipients given");
                if (out == null) failUsage("No output file specified");
                if (p11_library_required && p11_library == null)
                    failUsage("PKCS#11 recipient given but no --library");
                encrypt(version, out, files);
                break;
            case DECRYPT:
                if (files.isEmpty()) failUsage("No file to decrypt");
                if (key.isPKCS11() && p11_library == null)
                    failUsage("PKCS#11 slot given but no --library");
                decrypt(files.get(0), (files.size() > 1) ? files.get(1) : null);
                break;
            case LOCKS:
                if (files.isEmpty()) failUsage("No file specified");
                locks(files.get(0));
                break;
        }
    }

    static void decrypt(String file, String outDir) {
        System.out.println("Decrypting file " + file);
        if ((key.lock_idx < 0) && (key.label == null) && (key.cert == null) && !key.isPKCS11()) {
            System.err.println("Either lock index, label, certificate or PKCS11 slot has to be specified");
            System.exit(1);
        }
        try {
            ToolCrypto crypto = new ToolCrypto(key, p11_library);

            IStreamSource src = new IStreamSource(new FileInputStream(file));

            CDocReader rdr = CDocReader.createReader(src, false, null, crypto, null);
            System.out.format("Reader created (version %d)\n", rdr.getVersion());

            LockVector locks = rdr.getLocks();
            if (key.lock_idx < 0) {
                if (key.cert != null) {
                    // Find lock by cert
                    key.lock_idx = (int) rdr.getLockForCert(key.cert);
                } else if (key.label != null) {
                    // Find lock by label
                    for (int idx = 0; idx < locks.size(); idx++) {
                        ee.ria.cdoc.Lock lock = locks.get(idx);
                        if (lock.getLabel().equals(key.label)) {
                            key.lock_idx = idx;
                            break;
                        }
                    }
                } else if (key.isPKCS11()) {
                    // Find lock by certificate read from the PKCS11 token
                    byte[] cert = crypto.readCertificate();
                    if (cert != null) {
                        key.lock_idx = (int) rdr.getLockForCert(cert);
                    }
                }
            }
            if (key.lock_idx < 0) {
                System.err.println("Lock not found: " + key.label);
                return;
            }
            if (key.lock_idx >= locks.size()) {
                System.err.println("Lock index out of range: " + (key.lock_idx + 1));
                return;
            }
            byte[] fmk = rdr.getFMK(key.lock_idx);
            rdr.beginDecryption(fmk);
            FileInfo fi = new FileInfo();
            long result = rdr.nextFile(fi);
            while (result == CDoc.OK) {
                System.out.format("File %s length %d\n", fi.getName(), fi.getSize());
                File ofile = (outDir != null) ? new File(outDir, fi.getName()) : new File(fi.getName());
                OutputStream ofs = new FileOutputStream(ofile);
                rdr.readFile(ofs);
                ofs.close();
                result = rdr.nextFile(fi);
            }
            rdr.finishDecryption();
        } catch (CDocException exc) {
            System.err.format("CDoc Exception %d: %s\n", exc.code, exc.getMessage());
        } catch (IOException exc) {
            System.err.println("IO Exception: " + exc.getMessage());
        }
    }

    static void encrypt(int version, String file, List<String> files)
    {
        try {
            ToolCrypto crypto = new ToolCrypto(recipients, p11_library);
            NetworkBackend network = new ToolNetwork();
            CDocWriter wrtr = CDocWriter.createWriter(version, file, null, crypto, network);
            for (RcptInfo rinfo : recipients) {
                Recipient rcpt = null;
                switch (rinfo.type) {
                    case PASSWORD:
                        rcpt = Recipient.makeSymmetric(rinfo.label, 600000);
                        break;
                    case PKEY:
                        rcpt = Recipient.makePublicKey(rinfo.label, rinfo.secret);
                        break;
                    case SKEY:
                        rcpt = Recipient.makeSymmetric(rinfo.label, 0);
                        break;
                    case P11_SYMMETRIC:
                        rcpt = Recipient.makeSymmetric(rinfo.label, 0);
                        break;
                    case P11_PKI:
                        byte[] pub = crypto.readPublicKey(rinfo);
                        if (pub == null) {
                            System.err.println("No such public key: " + rinfo.p11.key_label);
                            continue;
                        }
                        rcpt = Recipient.makePublicKey(rinfo.label, pub);
                        break;
                    case CERT:
                        rcpt = Recipient.makeCertificate(rinfo.label, rinfo.cert);
                        break;
                    default:
                        System.err.println("Unsupported recipient type");
                        System.exit(1);
                }
                long result = wrtr.addRecipient(rcpt);
                System.out.format("addRecipient: %d\n", result);
            }
            long result = wrtr.beginEncryption();
            System.out.format("beginEncryption: %d\n", result);
            for (String name : files) {
                System.out.format("Adding file %s\n", name);
                InputStream ifs = new FileInputStream(name);
                byte[] bytes = ifs.readAllBytes();
                ifs.close();
                result = wrtr.addFile(name, bytes.length);
                System.out.format("addFile: %d\n", result);
                result = wrtr.writeData(bytes);
                System.out.format("writeData: %d\n", result);
            }
            result = wrtr.finishEncryption();
            System.out.format("finishEncryption: %d\n", result);
        } catch (IOException exc) {
            System.err.println("IO Exception: " + exc.getMessage());
        } catch (CDocException exc) {
            System.err.format("CDoc Exception %d: %s\n", exc.code, exc.getMessage());
        }
    }

    static void locks(String path) {
        System.out.println("Parsing file " + path);
        CDocReader rdr = CDocReader.createReader(path, null, null, null);
        System.out.format("Reader created (version %d)\n", rdr.getVersion());
        LockVector locks = rdr.getLocks();
        for (int i = 0; i < locks.size(); i++) {
            ee.ria.cdoc.Lock lock = locks.get(i);
            System.out.format("Lock %d\n", i + 1);
            System.out.format("  label: %s\n", lock.getLabel());
            System.out.format("  type: %s\n", lock.getType());
        }
    }

    // Library file names produced by the CMake cdoc_java target: platform
    // suffix (jnilib/dylib/so/dll), with and without the debug postfix 'd'
    // (CMAKE_DEBUG_POSTFIX).
    private static final String[] JNI_LIB_NAMES = {
        "libcdoc_java.jnilib", "libcdoc_javad.jnilib",
        "libcdoc_java.dylib", "libcdoc_javad.dylib",
        "libcdoc_java.so", "libcdoc_javad.so",
        "cdoc_java.dll", "cdoc_javad.dll"
    };

    private static String findLibraryInDir(File dir) {
        for (String name : JNI_LIB_NAMES) {
            File f = new File(dir, name);
            if (f.isFile()) {
                return f.getAbsolutePath();
            }
        }
        return null;
    }

    /**
     * Locate and load the JNI library built by the project's CMake build.
     *
     * Resolution order:
     *   1. --library command line argument (explicit file)
     *   2. -Dcdoc.library=<file> system property
     *   3. jni.properties resource baked into the jar by Gradle
     *      (records the JNI library directory of the build)
     *   4. Well-known CMake build directories relative to the working dir
     *   5. java.library.path (System.loadLibrary)
     */
    static void loadLibrary(String library) {
        if (library != null) {
            System.load(new File(library).getAbsolutePath());
            return;
        }
        String prop = System.getProperty("cdoc.library");
        if (prop != null) {
            System.load(new File(prop).getAbsolutePath());
            return;
        }
        try (InputStream is = CDocTool.class.getResourceAsStream("jni.properties")) {
            if (is != null) {
                java.util.Properties props = new java.util.Properties();
                props.load(is);
                String dir = props.getProperty("jniLibDir");
                if (dir != null) {
                    String lib = findLibraryInDir(new File(dir));
                    if (lib != null) {
                        System.load(lib);
                        return;
                    }
                }
            }
        } catch (IOException exc) {
            // Fall through to directory scan
        }
        String[] candidates = {
            "../../build/macos/cdoc",
            "../../build/macos-debug/cdoc",
            "../../build/ninja/cdoc",
            "../../build/linux/cdoc",
            "../../build/cdoc",
            "../../../build/cdoc"
        };
        for (String d : candidates) {
            String lib = findLibraryInDir(new File(d));
            if (lib != null) {
                System.load(lib);
                return;
            }
        }
        // Glob fallback: ../../build/<preset>/cdoc
        File[] presets = new File("../../build").listFiles();
        if (presets != null) {
            java.util.Arrays.sort(presets);
            for (File p : presets) {
                String lib = findLibraryInDir(new File(p, "cdoc"));
                if (lib != null) {
                    System.load(lib);
                    return;
                }
            }
        }
        // Last resort: search java.library.path
        try {
            System.loadLibrary("cdoc_java");
        } catch (UnsatisfiedLinkError err) {
            System.loadLibrary("cdoc_javad"); // debug build
        }
    }

    private static class ToolNetwork extends NetworkBackend {
        @Override
        public long getPeerTLSCertificates(CertificateList dst, String url) throws CDocException {
            return CDoc.OK;
        }
    }

    /**
     * PKCS#11 backend bound to the RcptInfo list: connectToKey pulls slot,
     * PIN (stored in secret), key id and key label from the RcptInfo of the
     * lock being processed, mirroring ToolPKCS11 in CDocCipher.cpp.
     */
    private static class ToolPKCS11 extends PKCS11Backend {
        private final List<RcptInfo> recipients;
        private final RcptInfo key;

        ToolPKCS11(String library, List<RcptInfo> recipients) {
            super(library);
            this.recipients = recipients;
            this.key = null;
        }

        ToolPKCS11(String library, RcptInfo key) {
            super(library);
            this.recipients = null;
            this.key = key;
        }

        private RcptInfo rcptFor(int idx) {
            if (key != null) return key;
            for (RcptInfo rinfo : recipients) {
                if (rinfo.lock_idx == idx) return rinfo;
            }
            return null;
        }

        @Override
        public long connectToKey(int idx, boolean priv) throws CDocException {
            RcptInfo rinfo = rcptFor(idx);
            if (rinfo == null) return CDoc.INTERNAL_ERROR;
            if (priv) {
                return usePrivateKey(rinfo.p11.slot, rinfo.secret, rinfo.p11.key_id, rinfo.p11.key_label);
            }
            return useSecretKey(rinfo.p11.slot, rinfo.secret, rinfo.p11.key_id, rinfo.p11.key_label);
        }
    }

    /**
     * Crypto backend for both encryption and decryption:
     *  - getSecret supplies password / symmetric key / PIN material
     *  - PKCS11 recipients delegate the key operations to a PKCS11Backend
     *  - --pkey/--pfkey decryption uses a local private key (via JCE)
     */
    private static class ToolCrypto extends CryptoBackend {
        private final List<RcptInfo> recipients;
        private PKCS11Backend p11;
        private PrivateKey privKey;

        public ToolCrypto(List<RcptInfo> recipients, String p11_library) {
            this.recipients = recipients;
            if (p11_library != null) {
                this.p11 = new ToolPKCS11(p11_library, recipients);
            }
        }

        public ToolCrypto(RcptInfo key, String p11_library) {
            this(List.of(key), p11_library);
        }

        private RcptInfo rcptFor(int idx) {
            for (RcptInfo rinfo : recipients) {
                if (rinfo.lock_idx == idx) return rinfo;
            }
            return null;
        }

        /** Read the certificate of the PKCS11 key (decryption, single key). */
        public byte[] readCertificate() throws CDocException {
            RcptInfo rinfo = recipients.get(0);
            DataBuffer buf = new DataBuffer();
            p11.getCertificate(buf, rinfo.p11.slot, rinfo.secret, rinfo.p11.key_id, rinfo.p11.key_label);
            return buf.getData();
        }

        /** Read the public key of a PKCS11 recipient (encryption). */
        public byte[] readPublicKey(RcptInfo rinfo) throws CDocException {
            DataBuffer buf = new DataBuffer();
            p11.getPublicKey(buf, rinfo.p11.slot, rinfo.secret, rinfo.p11.key_id, rinfo.p11.key_label);
            return buf.getData();
        }

        @Override
        public long random(DataBuffer dst, int size) throws CDocException {
            SecureRandom random = new SecureRandom();
            byte bytes[] = new byte[size];
            random.nextBytes(bytes);
            dst.setData(bytes);
            return CDoc.OK;
        }

        @Override
        public long getSecret(DataBuffer dst, int idx) {
            RcptInfo rinfo = rcptFor(idx);
            if (rinfo == null) return CDoc.NOT_FOUND;
            if (rinfo.secret == null) return CDoc.WRONG_ARGUMENTS;
            dst.setData(rinfo.secret);
            return CDoc.OK;
        }

        @Override
        public long deriveECDH1(DataBuffer dst, byte[] publicKey, int idx) throws CDocException {
            RcptInfo rinfo = rcptFor(idx);
            if ((rinfo != null) && rinfo.isPKCS11() && (p11 != null)) {
                return p11.deriveECDH1(dst, publicKey, idx);
            }
            try {
                PrivateKey priv = loadPrivateKey(rinfo);
                // libcdoc stores the ephemeral public key as a raw ANSI X9.62
                // uncompressed point (0x04 || X || Y), not as X.509 SPKI.
                if (publicKey.length < 1 || publicKey[0] != 4) return CDoc.CRYPTO_ERROR;
                int coordLen = (publicKey.length - 1) / 2;
                BigInteger x = new BigInteger(1, Arrays.copyOfRange(publicKey, 1, 1 + coordLen));
                BigInteger y = new BigInteger(1, Arrays.copyOfRange(publicKey, 1 + coordLen, publicKey.length));

                // Take the curve parameters from our own private key
                var params = ((ECPrivateKey) priv).getParams();
                PublicKey peer = KeyFactory.getInstance("EC").generatePublic(
                        new ECPublicKeySpec(new ECPoint(x, y), params));

                KeyAgreement ka = KeyAgreement.getInstance("ECDH");
                ka.init(priv);
                ka.doPhase(peer, true);
                dst.setData(ka.generateSecret());
                return CDoc.OK;
            } catch (Exception e) {
                return CDoc.CRYPTO_ERROR;
            }
        }

        @Override
        public long decryptRSA(DataBuffer dst, byte[] data, boolean oaep, int idx) throws CDocException {
            RcptInfo rinfo = rcptFor(idx);
            if ((rinfo != null) && rinfo.isPKCS11() && (p11 != null)) {
                return p11.decryptRSA(dst, data, oaep, idx);
            }
            try {
                PrivateKey priv = loadPrivateKey(rinfo);
                javax.crypto.Cipher cipher;
                if (oaep) {
                    // CDoc2 uses OAEP with SHA-256 for both digests
                    cipher = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                    cipher.init(javax.crypto.Cipher.DECRYPT_MODE, priv,
                            new OAEPParameterSpec("SHA-256", "MGF1",
                                    MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
                } else {
                    // CDoc1 uses PKCS#1 v1.5
                    cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher.init(javax.crypto.Cipher.DECRYPT_MODE, priv);
                }
                dst.setData(cipher.doFinal(data));
                return CDoc.OK;
            } catch (Exception e) {
                return CDoc.CRYPTO_ERROR;
            }
        }

        @Override
        public long extractHKDF(DataBuffer dst, byte[] salt, byte[] pw_salt, int kdf_iter, int idx) throws CDocException {
            RcptInfo rinfo = rcptFor(idx);
            if ((rinfo != null) && rinfo.isPKCS11() && (p11 != null)) {
                // PKCS11Backend.extractHKDF still uses the byte[] kek typemap;
                // bridge through it and store the result into the DataBuffer.
                byte[] kek = new byte[32];
                long result = p11.extractHKDF(kek, salt, pw_salt, kdf_iter, idx);
                dst.setData(kek);
                return result;
            }
            // Mirror the default CryptoBackend::extractHKDF: get key material
            // (PBKDF2 of the secret for password locks, the raw key for
            // symmetric locks) and HKDF-extract it with the lock salt.
            if ((salt == null) || (salt.length == 0)) return CDoc.WRONG_ARGUMENTS;
            if ((rinfo == null) || (rinfo.secret == null)) return CDoc.WRONG_ARGUMENTS;
            try {
                byte[] key_material;
                if (kdf_iter > 0) {
                    if ((pw_salt == null) || (pw_salt.length == 0)) return CDoc.WRONG_ARGUMENTS;
                    char[] pw = new char[rinfo.secret.length];
                    for (int i = 0; i < pw.length; i++) pw[i] = (char) (rinfo.secret[i] & 0xff);
                    key_material = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                            .generateSecret(new javax.crypto.spec.PBEKeySpec(pw, pw_salt, kdf_iter, 256))
                            .getEncoded();
                } else {
                    key_material = rinfo.secret;
                    if (key_material.length != 32) return CDoc.WRONG_ARGUMENTS;
                }
                javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
                mac.init(new javax.crypto.spec.SecretKeySpec(salt, "HmacSHA256"));
                dst.setData(mac.doFinal(key_material));
                return CDoc.OK;
            } catch (Exception e) {
                return CDoc.CRYPTO_ERROR;
            }
        }

        @Override
        public long sign(DataBuffer dst, CryptoBackend.HashAlgorithm algorithm, byte[] digest, int idx) throws CDocException {
            RcptInfo rinfo = rcptFor(idx);
            if ((rinfo != null) && rinfo.isPKCS11() && (p11 != null)) {
                return p11.sign(dst, algorithm, digest, idx);
            }
            return CDoc.NOT_IMPLEMENTED;
        }

        // Local private key operations (--pkey / --pfkey decryption)

        private PrivateKey loadPrivateKey(RcptInfo rinfo) throws Exception {
            if (privKey == null) {
                if ((rinfo == null) || (rinfo.secret == null)) throw new IllegalArgumentException("No private key");
                privKey = loadPrivateKey(rinfo.secret);
            }
            return privKey;
        }

        private static PrivateKey loadPrivateKey(byte[] der) throws Exception {
            // Accept both PKCS#8 keys and bare SEC1 EC keys (RFC 5915
            // ECPrivateKey). Wrap SEC1 into a PKCS#8 envelope so that Java's
            // KeyFactory can parse it.
            for (String algo : new String[]{"EC", "RSA"}) {
                for (byte[] candidate : new byte[][]{der, wrapSec1IfNeeded(der)}) {
                    if (candidate == null) continue;
                    try {
                        return KeyFactory.getInstance(algo).generatePrivate(new PKCS8EncodedKeySpec(candidate));
                    } catch (Exception e) {
                        // try next
                    }
                }
            }
            throw new IllegalArgumentException("Unsupported private key format");
        }

        /** Wrap a bare SEC1 ECPrivateKey into a PKCS#8 PrivateKeyInfo. */
        private static byte[] wrapSec1IfNeeded(byte[] der) {
            // After the outer SEQUENCE tag+length, the first field is INTEGER:
            // value 0 means PKCS#8 (version), value 1 means SEC1 ECPrivateKey.
            int i = 1; // skip SEQUENCE tag
            if ((der[i] & 0x80) != 0) i += (der[i] & 0x7f); // skip long-form length bytes
            i++; // skip length byte
            if (i >= der.length || der[i] != 0x02) return null; // expected INTEGER
            int intVal = der[i + 2] & 0xff;
            if (intVal != 1) return null; // not SEC1

            // Find the curve OID (first 0x06 tag after the private key OCTET STRING)
            int oidPos = -1;
            for (int p = i + 3; p < der.length - 2; p++) {
                if (der[p] == 0x06) { oidPos = p; break; }
            }
            if (oidPos < 0) return null;
            int oidLen = der[oidPos + 1] & 0xff;
            byte[] oid = Arrays.copyOfRange(der, oidPos, oidPos + 2 + oidLen);

            // AlgorithmIdentifier = SEQUENCE { id-ecPublicKey OID, curve OID }
            byte[] idEcPublicKey = {0x06, 0x07, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01};
            byte[] algId = seq(concat(idEcPublicKey, oid));
            // PKCS#8 = SEQUENCE { INTEGER 0, algId, OCTET STRING (sec1 der) }
            byte[] body = concat(new byte[]{0x02, 0x01, 0x00}, algId);
            body = concat(body, octetString(der));
            return seq(body);
        }

        private static byte[] concat(byte[] a, byte[] b) {
            byte[] r = Arrays.copyOf(a, a.length + b.length);
            System.arraycopy(b, 0, r, a.length, b.length);
            return r;
        }

        private static byte[] seq(byte[] content) { return tlv(0x30, content); }
        private static byte[] octetString(byte[] content) { return tlv(0x04, content); }

        private static byte[] tlv(int tag, byte[] content) {
            int len = content.length;
            byte[] header;
            if (len < 128) {
                header = new byte[]{(byte) tag, (byte) len};
            } else if (len < 256) {
                header = new byte[]{(byte) tag, (byte) 0x81, (byte) len};
            } else {
                header = new byte[]{(byte) tag, (byte) 0x82, (byte) (len >> 8), (byte) len};
            }
            return concat(header, content);
        }
    }

    private static class JavaLogger extends Logger {
        @Override
        public void logMessage(LogLevel level, String file, int line, String message) {
            System.out.format("%s:%s %s %s\n", file, line, level, message);
        }
    }
}
