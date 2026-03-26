package ee.ria.cdoc;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Collection;
import java.util.HexFormat;
import java.util.concurrent.locks.Lock;

public class CDocTool {
    private enum Action {
        INVALID,
        ENCRYPT,
        DECRYPT,
        LOCKS,
        TEST
    }

    private static HexFormat hex = HexFormat.of();

    public static String getArg(int arg_idx, String[] args) {
        arg_idx += 1;
        if (arg_idx >= args.length) {
            System.err.println("Invalid arguments");
            System.exit(1);
        }
        return args[arg_idx];
    }

    // Make logger static to ensure that it is not garbage-collected as long as it is attached to library
    private static Logger logger;
    
    public static void main(String[] args) {
        System.out.println("Starting app...");

        LogLevel log_level = LogLevel.LEVEL_INFO;
        String library = "../../build/macos/cdoc/libcdoc_javad.jnilib";
        Action action = Action.INVALID;
        ArrayList<String> files = new ArrayList<>();
        int version = 2;
        String label = null;
        String password = null;
        String out = "test.cdoc2";
        String certfile = null;
        // PKSC11 parameters
        String p11library = null;
        int p11slot = -1;
        byte[] p11pin = null;
        byte[] p11id = null;
        String p11label = null;
        // Keyshare parameters
        String personal_code = null;
        String server_id = null;
        String[] servers = null;
    
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("test")) {
                action = Action.TEST;
            } else if (args[i].equals("encrypt")) {
                action = Action.ENCRYPT;
            } else if (args[i].equals("decrypt")) {
                action = Action.DECRYPT;
            } else if (args[i].equals("locks")) {
                action = Action.LOCKS;
            } else if (args[i].equals("--label")) {
                label = getArg(i, args);
                i += 1;
            } else if (args[i].equals("--v1")) {
                version = 1;
            } else if (args[i].equals("--certfile")) {
                certfile = getArg(i, args);
                i += 1;
            } else if (args[i].equals("--library")) {
                library = getArg(i, args);
                i += 1;
            } else if (args[i].equals("--p11library")) {
                p11library = getArg(i, args);
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
                password = args[i];
            } else if (args[i].equals("--personal-code")) {
                i += 1;
                if (i >= args.length) {
                    System.err.println("Invalid arguments");
                    System.exit(1);
                }
                personal_code = args[i];
            } else if (args[i].equals("--servers")) {
                i += 1;
                if (i >= args.length) {
                    System.err.println("Invalid arguments");
                    System.exit(1);
                }
                server_id = args[i];
                i += 1;
                if (i >= args.length) {
                    System.err.println("Invalid arguments");
                    System.exit(1);
                }
                servers = args[i].split(",");
            } else if (args[i].equals("--log-level")) {
                i += 1;
                if (i >= args.length) {
                    System.err.println("Invalid arguments");
                    System.exit(1);
                }
                log_level = LogLevel.valueOf(args[i]);
            } else if (!args[i].startsWith("--")) {
                files.add(args[i]);
            }
        }

        File lib = new File(library);
        System.load(lib.getAbsolutePath());
        System.out.println("Library loaded");

        logger =  new JavaLogger();
        logger.setMinLogLevel(log_level);
        CDoc.setLogger(logger);
        CDoc.log(LogLevel.LEVEL_DEBUG, "FILENAME", 0, "Starting CDocTool.java");

        switch (action) {
            case ENCRYPT:
            if (certfile != null) {
                encryptCertFile(version, out, label, certfile, files);
            } else if (password != null) {
                encrypt(out, label, password, files);
            } else if (servers != null) {
                encryptShares(out, label, personal_code, server_id, servers, files);
            }
                break;
            case DECRYPT:
                if (certfile != null) {
                    decryptForCert(files.get(0), certfile);
                    break;
                }
                if (p11library != null) {
                    decrypt(files.get(0), label, password);
                } else {
                    decrypt(files.get(0), label, password);
                }
                break;
            case LOCKS:
                locks(files.get(0));
                break;
            case TEST:
                test();
                break;
        }
    }

    static void decrypt(String file, String p11library, int p11slot, byte[] p11pin, byte[] p11id, String p11label) {
        System.out.println("Decrypting file (P11) " + file);
    }

    static void decryptForCert(String file, String certfile) {
        try {
            ToolConf conf = new ToolConf();
            IStreamSource src = new IStreamSource(new FileInputStream(file));
            CDocReader rdr = CDocReader.createReader(src, false, conf, null, null);

            LockVector locks = rdr.getLocks();
            System.err.println("Num locks " + locks.size());

            InputStream ifs = new FileInputStream(certfile);
            byte[] cert = ifs.readAllBytes();

            long idx = rdr.getLockForCert(cert);
            System.err.println("Lock idx " + idx);
            ee.ria.cdoc.Lock lock = locks.get((int) idx);
            System.err.println("Lock label " + lock.getLabel());

        } catch (CDocException exc) {
            System.err.println("CDoc exception");
            System.err.println(exc.getMessage());
        } catch (IOException exc) {
            // Caught CDoc exception
        }
    }

    static void decrypt(String file, String label, String password) {
        System.out.println("Decrypting file " + file);
        try {
            ToolConf conf = new ToolConf();
            DataBuffer buf = new DataBuffer();
            ToolCrypto crypto = new ToolCrypto();
            crypto.setPassword(password);

            IStreamSource src = new IStreamSource(new FileInputStream(file));

            CDocReader rdr = CDocReader.createReader(src, false, conf, crypto, null);
            System.out.format("Reader created (version %d)\n", rdr.getVersion());

            LockVector locks = rdr.getLocks();
            for (int idx = 0; idx < locks.size(); idx++) {
                ee.ria.cdoc.Lock lock = locks.get(idx);
                if (lock.getLabel().equals(label)) {
                    System.out.format("Found lock: %s\n", label);
                    byte[] fmk = rdr.getFMK(idx);
                    System.out.format("FMK is: %s\n", hex.formatHex(fmk));
                    System.out.format("Stored data is: %s\n", hex.formatHex(stored.getData()));
                    rdr.beginDecryption(fmk);
                    FileInfo fi = new FileInfo();
                    long result = rdr.nextFile(fi);
                    System.out.format("nextFile result: %d\n", result);
                    try {
                        while (result == CDoc.OK) {
                            System.out.format("File %s length %d\n", fi.getName(), fi.getSize());
                            File ofile = new File(fi.getName());
                            OutputStream ofs = new FileOutputStream(ofile.getName());
                            rdr.readFile(ofs);
                            result = rdr.nextFile(fi);
                        }
                    } catch (IOException exc) {
                        System.err.println("IO Exception: " + exc.getMessage());
                    }
                    rdr.finishDecryption();
                    return;
                }
            }
            System.err.format("No such lock: %s\n", label);
        } catch (CDocException exc) {
            // Caught CDoc exception
        } catch (IOException exc) {
            // Caught CDoc exception
        }
    }

    static void encryptShares(String file, String label, String personal_code, String server_id, String[] servers, Collection<String> files) {
        System.out.println("Creating file " + file);
        ToolConf conf = new ToolConf();
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
        ToolCrypto crypto = new ToolCrypto();
        NetworkBackend network = new ToolNetwork();
        CDocWriter wrtr = CDocWriter.createWriter(2, file, conf, null, network);
        try {
            Recipient rcpt = Recipient.makeShare(label, server_id, "PNOEE-" + personal_code);
            long result = wrtr.addRecipient(rcpt);
            result = wrtr.beginEncryption();
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

    static void encrypt(String file, String label, String password, Collection<String> files) {
        System.out.println("Creating file " + file);
        ToolConf conf = new ToolConf();
        ToolCrypto crypto = new ToolCrypto();
        crypto.setPassword(password);
        CDocWriter wrtr = CDocWriter.createWriter(2, file, conf, crypto, null);
        try {
            long result = wrtr.beginEncryption();
            System.out.format("beginEncryption: %d\n", result);
            Recipient rcpt = Recipient.makeSymmetric(label, 65535);
            result = wrtr.addRecipient(rcpt);
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

    static void encryptCertFile(int version, String file, String label, String certfile, Collection<String> files) {
        System.out.println("Creating file " + file);
        ToolConf conf = new ToolConf();
        ToolNetwork network = new ToolNetwork();
        CDocWriter wrtr = CDocWriter.createWriter(version, file, conf, null, network);
        try {
            InputStream ifs = new FileInputStream(certfile);
            byte[] cert = ifs.readAllBytes();
            Recipient rcpt = Recipient.makeCertificate(label, cert);
            long result = wrtr.addRecipient(rcpt);
            System.out.format("addRecipient: %d\n", result);
            result = wrtr.beginEncryption();
            System.out.format("beginEncryption: %d\n", result);
            for (String name : files) {
                System.out.format("Adding file %s\n", name);
                ifs = new FileInputStream(name);
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
            System.out.format("Lock %d\n", i);
            System.out.format("  label: %s\n", lock.getLabel());
            System.out.format("  type: %s\n", lock.getType());
        }
    }

    static void test() {
        System.err.println("Testing label generation");
        String label = "data:v=1&type=ID-card&serial_number=PNOEE-38001085718&cn=J%C3%95EORG%2CJAAK-KRISTJAN%2C38001085718";
        java.util.Map<String,String> map = ee.ria.cdoc.Lock.parseLabel(label);
        for (String key : map.keySet()) {
            System.err.format("  %s:%s\n", key, map.get(key));
        }

        String path = "test.cdoc2";

        System.err.println("Creating ToolConf...");
        ToolConf conf = new ToolConf();

        System.err.println("Creating ToolCrypto");
        ToolCrypto crypto = new ToolCrypto();

        System.err.println("Creating ToolNetwork");
        ToolNetwork network = new ToolNetwork();

        System.err.println("Creating DataBuffer...");
        DataBuffer buf = new DataBuffer();
        byte[] bytes = {1, 2, 3};
        buf.setData(bytes);
        System.err.format("Buffer: %s\n", hex.formatHex(buf.getData()));

        System.err.println("Creating reader: " + path);
        CDocReader rdr = CDocReader.createReader(path, conf, null, network);
        System.err.format("Reader created (version %d)\n", rdr.getVersion());

        testRW(conf, crypto);
    
        System.err.println("Success");
    }

    static void testRW(ToolConf conf, ToolCrypto crypto) {
        try {
            final String container = "testfile.cdoc";
            final String password = "TereTalv!";
            final String label = "Jaanus Jõhvikas";

            crypto.setPassword(password);
            DataBuffer rnd = new DataBuffer();
            crypto.random(rnd, 57);
            System.gc();
            final byte[] datain = rnd.getData();
            System.out.format("Data IN: %s\n", hex.formatHex(datain));

            CDocWriter wrtr = CDocWriter.createWriter(2, container, conf, crypto, null);
            System.gc();
            Recipient rcpt = Recipient.makeSymmetric(label, 65535);
            long result = wrtr.addRecipient(rcpt);
            System.gc();
            System.out.format("addRecipient: %d\n", result);
            result = wrtr.beginEncryption();
            System.gc();
            System.out.format("beginEncryption: %d\n", result);
            final String name = "kala";
            System.out.format("Adding file %s\n", name);
            result = wrtr.addFile(name, datain.length);
            System.gc();
            System.out.format("addFile: %d\n", result);
            result = wrtr.writeData(datain);
            System.gc();
            System.out.format("writeData: %d\n", result);
            result = wrtr.finishEncryption();
            System.gc();
            System.out.format("finishEncryption: %d\n", result);

            CDocReader rdr = CDocReader.createReader(container, conf, crypto, null);
            System.gc();
            System.out.format("Reader created (version %d)\n", rdr.getVersion());
            LockVector locks = rdr.getLocks();
            System.gc();
            ee.ria.cdoc.Lock lock = locks.get(0);
            System.out.format("Lock: %s\n", lock.getLabel());
            byte[] fmk = rdr.getFMK(0);
            System.gc();
            System.out.format("FMK is: %s\n", hex.formatHex(fmk));
            rdr.beginDecryption(fmk);
            System.gc();
            FileInfo fi = new FileInfo();
            result = rdr.nextFile(fi);
            System.gc();
            System.out.format("nextFile result: %d\n", result);
            while (result == CDoc.OK) {
                System.out.format("File %s length %d\n", fi.getName(), fi.getSize());
                byte[] dataout = new byte[(int) fi.getSize()];
                rdr.readData(dataout);
            System.gc();
                System.out.format("Data OUT: %s\n", hex.formatHex(dataout));
                result = rdr.nextFile(fi);
            }
            rdr.finishDecryption();
            System.gc();
        } catch (CDocException exc) {
                System.err.format("CDoc Exception %d: %s\n", exc.code, exc.getMessage());
        }
    }

    private static class ToolConf extends Configuration  {
        public final HashMap<String,Object> values = new HashMap<>();

        @Override
        public String getValue(String domain, String param) {
            HashMap<String,Object> map = values;
            for (String str : map.keySet()) {
                System.err.println("Key:" + str);
            }
            if ((domain != null) && !domain.isEmpty()) {
                Object obj = map.get(domain);
                if ((obj == null) || !(obj instanceof HashMap)) {
                    System.err.format("%s is not a valid configuration domain\n", domain);
                    System.exit(1);
                }
                map = (HashMap<String,Object>) obj;
                for (String str : map.keySet()) {
                    System.err.println("Key:" + str + " value " + map.get(str));
                }
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

    private static DataBuffer stored = null;

    private static class ToolCrypto extends CryptoBackend {
        private byte[] secret;
        
        void setPassword(String password) {
            this.secret = password.getBytes();
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
            dst.setData(secret);
            return CDoc.OK;
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
