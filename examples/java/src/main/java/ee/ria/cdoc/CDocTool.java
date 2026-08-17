package ee.ria.cdoc;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.nio.file.Files;
import java.nio.file.Paths;

public class CDocTool {
    private enum Action {
        INVALID,
        ENCRYPT,
        DECRYPT,
        LOCKS
    }

    private static HexFormat hex = HexFormat.of();

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
        CDocTool LIBRARY ACTION ARGUMENTS FILE(S)

        Library: path to libcdoc JNI library

        Actions:
            encrypt     Encrypt files (symmetric, certificate, or keyshare)
            decrypt     Decrypt files
            locks       List locks in a CDoc file
        
        Encryption arguments:
            --rcpt RECIPIENT        Recipient info, where recipient is one of the following:
                <label>:cert:CERTIFICATE_FILE     - public key from certificate file (DER format).
                <label>:pkey:HEX_KEY         - hex encoded public key (DER format; rsa, secp384r1, secp256r1 or secp521r1 key).
                <label>:pfkey:FILENAME      - public key from file (DER format; rsa, secp384r1, secp256r1 or secp521r1 key).
                <label>:skey:PUBLIC_KEY     - AES key, hex encoded.
                <label>:pw:PASS           - AES key derived from password with PWBKDF.
                <label>:p11pk:PKCS11_SLOT[:PIN][:KEY_ID][:KEY_LABEL]  - use AES key from PKCS11 module.
                <label>:p11sk:PKCS11_SLOT[:PIN][:KEY_ID][:KEY_LABEL]  - use public key from PKCS11 module.
                <label>:share:ID          - keyshares with given ID (personal code).
            --v1                      - creates CDOC1 version container. Supported only for encryption with certificate.
            --label <label>         Recipient label
            --password <pass>       Password for symmetric encryption
            --cert <file>       Certificate file for certificate-based encryption
            --servers <id> <urls>  Keyshare server configuration
            --personal-code <code> Personal code for keyshare
            --p11library <lib>   PKCS#11 library path
            --p11slot <slot>      PKCS#11 slot number
            --p11pin <pin>        PKCS#11 PIN
            --p11id <id>         PKCS#11 key ID
            --p11label <label>    PKCS#11 key label
        Decryption arguments:
            --password <pass>    Password for symmetric decryption
        Common arguments:
            --library <file>     Library path (default ./libcdoc_javad.jnilib)
            --v1                 Use CDoc version 1
            --out <file>         Output file
            --lock-idx <idx>     Lock index (for decryption)
            --log-level <level>  Log level (DEBUG, INFO, WARN, ERROR)
        Recipient types:
            [label]:cert:CERTIFICATE_FILE     - public key from certificate file (DER format)
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
            SHARE
        }
        public static final class P11Info {
            public int slot = -1;
            public byte[] key_id = null;
            public String key_label = null;
        }
        public Type type;
        public String label;
        public byte[] cert;
        public byte[] secret;
        public String id;
        public String file;
        public int lock_idx = -1;
        public P11Info p11;
    }

    private static final ArrayList<RcptInfo> recipients = new ArrayList<>();
    private static boolean libary_required = false;

    private static String library = "../../build/macos/cdoc/libcdoc_javad.jnilib";
    private static LogLevel log_level = LogLevel.LEVEL_WARNING;

    private static int parseRcpt(int arg_idx, String[] args) {
        if (args[arg_idx].equals("--rcpt")) {
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
                        if (parts.length != 3) failUsage("skey format: label:skey:PUBLIC_KEY");
                        rcpt.type = RcptInfo.Type.SKEY;
                        rcpt.secret = hex.parseHex(parts[2]);
                        break;
                    case "pw":
                        rcpt.type = RcptInfo.Type.PASSWORD;
                        rcpt.secret = parts[2].getBytes();
                        break;
                    case "p11pk":
                    case "p11sk":
                        libary_required = true;
                        rcpt.type = (parts[1].equals("p11sk")) ? RcptInfo.Type.P11_SYMMETRIC : RcptInfo.Type.P11_PKI;
                        rcpt.p11 = new RcptInfo.P11Info();
                        if (parts[2].startsWith("0x")) {
                            rcpt.p11.slot = Integer.parseInt(parts[2].substring(2), 16);
                        } else {
                            rcpt.p11.slot = Integer.parseInt(parts[2]);
                        }
                        if (parts.length > 3) {
                            rcpt.secret = hex.parseHex(parts[3]);
                        }
                        if (parts.length > 4) {
                            rcpt.p11.key_id = hex.parseHex(parts[4]);
                        }
                        if (parts.length > 5) {
                            rcpt.p11.key_label = parts[5];
                        }
                        break;
                    case "share":
                        if (parts.length != 3) failUsage("share format: label:share:ID");
                        rcpt.type = RcptInfo.Type.SHARE;
                        rcpt.id = parts[2];
                        break;
                    default:
                        failUsage("Unsupported recipient type: " + parts[1]);
                }
                recipients.add(rcpt);
                return 2;
            } catch (Exception e) {
                failUsage(String.format("Error parsing recipient %s: %s", rcpt_str, e.getMessage()));
            }
        }
        return 0;
    }

    private static int version = 2;
    private static String out = "test.cdoc2";
    private static String p11_library = null;
    private static String server_id = null;
    private static String auth_server = null;
    private static String rp_server = null;

    private static int parseCommon(int arg_idx, String[] args, ToolConf conf) {
        if (args[arg_idx].equals("--library")) {
            library = getArg(arg_idx, args);
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
        } else if (args[arg_idx].equals("--p11library")) {
            p11_library = getArg(arg_idx, args);
            return 2;
        } else if (args[arg_idx].equals("--share-servers")) {
            server_id = getArg(arg_idx, args);
            arg_idx += 1;
            String str = getArg(arg_idx, args);
            String[] servers = str.split(",");
            HashMap<String,Object> map = new HashMap<>();
            // Put JSON list of server urls
            StringBuilder bldr = new StringBuilder();
            bldr.append("[");
            for (int i = 0; i < servers.length; i++) {
                if (i > 0) bldr.append(",");
                bldr.append("\"");
                bldr.append(servers[i]);
                bldr.append("\"");
            }
            bldr.append("]");
            map.put(Configuration.SHARE_SERVER_URLS, bldr.toString());
            conf.values.put(server_id, map);
            return 3;
        } else if (args[arg_idx].equals("--auth-server")) {
            auth_server = getArg(arg_idx, args);
            return 2;
        } else if (args[arg_idx].equals("--rp-server")) {
            rp_server = getArg(arg_idx, args);
            return 2;
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
            library = getArg(arg_idx, args);
            arg_idx += 2;
        }
        if (arg_idx >= args.length) {
            failUsage("No action specified");
        }

        File lib = new File(library);
        System.load(lib.getAbsolutePath());
        System.out.format("Library %s loaded\n", library);

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
                failUsage("Invalid action: " + args[0]);
        }


        ArrayList<String> files = new ArrayList<>();
        // PKSC11 parameters
        int p11slot = -1;
        byte[] p11pin = null;
        byte[] p11id = null;
        String p11label = null;
        // Keyshare parameters
        String personal_code = null;
    
        ToolConf conf = new ToolConf();
        RcptInfo rcpt = new RcptInfo();

        int i = arg_idx + 1;
        try {
            while (i < args.length) {
                int n_args = parseCommon(i, args, conf);
                if (n_args == 0) {
                    n_args = parseRcpt(i, args);
                }
                if (n_args > 0) {
                    i += n_args;
                    continue;
                }

                if (args[i].equals("--label")) {
                    rcpt.label = getArg(i, args);
                    i += 1;
                } else if (args[i].equals("--lock-idx")) {
                    rcpt.lock_idx = Integer.parseInt(getArg(i, args)) - 1;
                    i += 1;
                } else if (args[i].equals("--cert")) {
                    rcpt.cert = Files.readAllBytes(Paths.get(getArg(i, args)));
                    i += 1;
                } else if (args[i].equals("--p11slot")) {
                    p11slot = Integer.parseInt(getArg(i, args));
                    i += 1;
                } else if (args[i].equals("--p11pin")) {
                    p11pin = getArg(i, args).getBytes();
                    i += 1;
                } else if (args[i].equals("--p11pin")) {
                    p11id = getArg(i, args).getBytes();
                    i += 1;
                } else if (args[i].equals("--p11label")) {
                    p11label = getArg(i, args);
                    i += 1;
                } else if (args[i].equals("--password")) {
                    i += 1;
                    if (i >= args.length) {
                        System.err.println("Invalid arguments");
                        System.exit(1);
                    }
                    rcpt.secret = args[i].getBytes();
                } else if (args[i].equals("--personal-code")) {
                    i += 1;
                    if (i >= args.length) {
                        System.err.println("Invalid arguments");
                        System.exit(1);
                    }
                    personal_code = args[i];
                } else if (!args[i].startsWith("--")) {
                    files.add(args[i]);
                }
                i += 1;
            }
        } catch (IOException exc) {
            System.err.println("IO Exception: " + exc.getMessage());
            System.exit(1);
        }

        logger =  new JavaLogger();
        logger.setMinLogLevel(log_level);
        CDoc.setLogger(logger);
        CDoc.log(LogLevel.LEVEL_DEBUG, "FILENAME", 0, "Starting CDocTool.java");

        switch (action) {
            case ENCRYPT:
                encrypt(version, out, files, conf);
                break;
            case DECRYPT:
                decrypt(files.get(0), rcpt);
                break;
            case LOCKS:
                locks(files.get(0));
                break;
        }
    }

    static void decrypt(String file, RcptInfo rcpt) {
        System.out.println("Decrypting file " + file);
        if ((rcpt.lock_idx < 0) && (rcpt.label == null) && (rcpt.cert == null)) {
            System.err.println("Either lock index, label or certificate has to be specified");
            System.exit(1);
        }
        try {
            ToolConf conf = new ToolConf();
            DataBuffer buf = new DataBuffer();
            ToolCrypto crypto = new ToolCrypto(rcpt);

            IStreamSource src = new IStreamSource(new FileInputStream(file));

            CDocReader rdr = CDocReader.createReader(src, false, conf, crypto, null);
            System.out.format("Reader created (version %d)\n", rdr.getVersion());

            LockVector locks = rdr.getLocks();
            if (rcpt.lock_idx < 0) {
                if (rcpt.cert != null) {
                    // Find lock by cert
                    rcpt.lock_idx = (int) rdr.getLockForCert(rcpt.cert);
                } else if (rcpt.label != null) {
                    // Find lock by label
                    for (int idx = 0; idx < locks.size(); idx++) {
                        ee.ria.cdoc.Lock lock = locks.get(idx);
                        if (lock.getLabel().equals(rcpt.label)) {
                            rcpt.lock_idx = idx;
                            break;
                        }
                    }
                }
            }
            if (rcpt.lock_idx < 0) {
                System.err.println("Lock not found: " + rcpt.label);
                return;
            }
            if (rcpt.lock_idx >= locks.size()) {
                System.err.println("Lock index out of range: " + rcpt.lock_idx);
                return;
            }
            byte[] fmk = rdr.getFMK(rcpt.lock_idx);
            rdr.beginDecryption(fmk);
            FileInfo fi = new FileInfo();
            long result = rdr.nextFile(fi);
            System.out.format("nextFile result: %d\n", result);
            while (result == CDoc.OK) {
                System.out.format("File %s length %d\n", fi.getName(), fi.getSize());
                File ofile = new File(fi.getName());
                OutputStream ofs = new FileOutputStream(ofile.getName());
                rdr.readFile(ofs);
                result = rdr.nextFile(fi);
            }
            rdr.finishDecryption();
        } catch (CDocException exc) {
            // Caught CDoc exception
            System.err.format("CDoc Exception %d: %s\n", exc.code, exc.getMessage());
        } catch (IOException exc) {
            // Caught CDoc exception
            System.err.println("IO Exception: " + exc.getMessage());
        }
    }

    static void encrypt(int version, String file, List<String> files, Configuration conf)
    {
        try {
            ToolCrypto crypto = new ToolCrypto(recipients);
            NetworkBackend network = new ToolNetwork();
            CDocWriter wrtr = CDocWriter.createWriter(version, file, conf, null, network);
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
                    case P11_PKI:
                        break;
                    case CERT:
                        rcpt = Recipient.makeCertificate(rinfo.label, rinfo.cert);
                        break;
                    case SHARE:
                        rcpt = Recipient.makeShare(rinfo.label, server_id, "PNOEE-" + rinfo.id);
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
            System.out.format("addRecipient: %d\n", result);
            for (String name : files) {
                System.out.format("Adding file %s\n", name);
                InputStream ifs = new FileInputStream(name);
                byte[] bytes = ifs.readAllBytes();
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

    ///
    /// A simple Configuration implementation for CDocTool
    ///
    private static class ToolConf extends Configuration  {
        public final HashMap<String,Object> values = new HashMap<>();

        @Override
        public String getValue(String domain, String param) {
            HashMap<String,Object> map = values;
            if ((domain != null) && !domain.isEmpty()) {
                Object obj = map.get(domain);
                if ((obj == null) || !(obj instanceof HashMap)) {
                    System.err.format("%s is not a valid configuration domain\n", domain);
                    System.exit(1);
                }
                map = (HashMap<String,Object>) obj;
            }
            if (!map.containsKey(param)) {
                System.err.format("No such parameter: %s\n", param);
                return null;
            }
            Object obj = map.get(param);
            if ((obj == null) || !(obj instanceof String)) {
                System.err.format("%s is not a valid configuration entry\n", param);
                System.exit(1);
            }
            String str = (String) obj;
            System.err.format("Conf value: %s\n", str);
            return str;
        }

        public long test(DataBuffer dst) {
            System.err.println("ToolConf.test: Java subclass implementation");
            //System.err.println("CPtr is: " + dst.getCPtr());
            Object obj = (Object) dst;
            System.err.println("ToolConf:Class: " + obj.getClass());
            System.err.println("ToolConf:Buffer is: " + dst.getData());
            byte[] bytes = {4, 5, 6, 7, 8};
            System.err.format("ToolConf:Buffer in: %s\n", hex.formatHex(dst.getData()));
            dst.setData(bytes);
            System.err.format("ToolConf:Buffer out: %s\n", hex.formatHex(dst.getData()));
            return CDoc.OK;
        }
    }

    private static class ToolCrypto extends CryptoBackend {
        private final List<RcptInfo> recipients;
        
        public ToolCrypto(List<RcptInfo> recipients) {
            this.recipients = recipients;
        }

        public ToolCrypto(RcptInfo rinfo) {
            this.recipients = new ArrayList<>();
            this.recipients.add(rinfo);
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
            for (RcptInfo rinfo : recipients) {
                if (rinfo.lock_idx == idx) {
                    dst.setData(rinfo.secret);
                    return CDoc.OK;
                }
            }
            return CDoc.NOT_FOUND;
        }
    }

    private static class P11Crypto extends PKCS11Backend {
        public int slot;
        public byte[] pin;
        public byte[] key_id = null;
        public String key_label = null;

        public P11Crypto(String library) {
            super(library);
        }

        @Override
        public long connectToKey(int idx, boolean priv) throws CDocException {
            if (priv) {
                return usePrivateKey(slot, pin, key_id, key_label);
            }
            return CDoc.NOT_IMPLEMENTED;
        }
    }

    private static class ToolNetwork extends NetworkBackend {
        @Override
        public long getPeerTLSCertificates(CertificateList dst, String url) throws CDocException {
            System.err.println("ToolNetwork.getPeerTLSCertificates: " + dst);
            return CDoc.OK;
        }
    }

    private static class JavaLogger extends Logger {
        @Override
        public void logMessage(LogLevel level, String file, int line, String message) {
            System.out.format("%s:%s %s %s\n", file, line, level, message);
        }
    }
}
