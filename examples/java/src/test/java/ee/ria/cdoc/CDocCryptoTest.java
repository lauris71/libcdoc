package ee.ria.cdoc;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import java.security.spec.MGF1ParameterSpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Round-trip tests for every libcdoc encryption method that works offline
 * (no PKCS11 token and no keyserver/network connection):
 *
 *   - password-based (PBKDF2) symmetric recipient
 *   - raw symmetric key recipient
 *   - ECC public key recipient (secp256r1, secp384r1, secp521r1)
 *   - RSA public key recipient
 *   - certificate recipient (both CDoc1 and CDoc2 containers)
 *   - a multi-recipient container mixing the above
 *
 * Test keys and certificates come from libcdoc's test/data directory.
 */
public class CDocCryptoTest {

    /** libcdoc/test/data, resolved relative to the project working directory */
    private static final File DATA_DIR = new File("../../test/data");

    private static final String EC256 = "ec-secp256r1";
    private static final String EC384 = "ec-secp384r1";
    private static final String EC521 = "ec-secp521r1";
    private static final String RSA = "rsa_2048";

    private static final byte[] PAYLOAD = "CDoc round-trip payload \u00f5\u00e4\u00f6\u00fc".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    @TempDir
    File tempDir;

    @BeforeAll
    static void loadLibrary() {
        CDocTool.loadLibrary(null);
    }

    // Password-based recipient (CDoc2)

    @Test
    void passwordCdoc2() throws Exception {
        String password = "TestPassword-123";
        File container = new File(tempDir, "password.cdoc2");
        Recipient rcpt = Recipient.makeSymmetric("pw-label", 600000);

        encrypt(container, 2, new SecretCrypto(password.getBytes()), rcpt);
        decrypt(container, new SecretCrypto(password.getBytes()), 0);
    }

    // Raw symmetric key recipient (CDoc2, kdf_iter = 0)

    @Test
    void symmetricKeyCdoc2() throws Exception {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) key[i] = (byte) (i * 7 + 1);
        File container = new File(tempDir, "skey.cdoc2");
        Recipient rcpt = Recipient.makeSymmetric("skey-label", 0);
        assertTrue(rcpt.validate());

        encrypt(container, 2, new SecretCrypto(key), rcpt);
        decrypt(container, new SecretCrypto(key), 0);
    }

    // ECC public key recipients (all three curves, CDoc2)

    @Test
    void eccPublicKeyCdoc2() throws Exception {
        eccRoundTrip(EC256);
        eccRoundTrip(EC384);
        eccRoundTrip(EC521);
    }

    private void eccRoundTrip(String stem) throws Exception {
        byte[] pub = readKey(stem + "-pub.der");
        byte[] priv = readKey(stem + "-priv.der");
        File container = new File(tempDir, stem + ".cdoc2");
        Recipient rcpt = Recipient.makePublicKey(stem + "-label", pub);
        assertFalse(rcpt.isEmpty());
        assertTrue(rcpt.isPKI());

        encrypt(container, 2, null, rcpt);
        decrypt(container, new KeyCrypto(priv), 0);
    }

    // RSA public key recipient (CDoc2, OAEP padding)

    @Test
    void rsaPublicKeyCdoc2() throws Exception {
        byte[] pub = readKey(RSA + "_pub.der");
        byte[] priv = readKey(RSA + "_priv.der");
        File container = new File(tempDir, "rsa.cdoc2");
        Recipient rcpt = Recipient.makePublicKey("rsa-label", pub);
        assertTrue(rcpt.isPKI());

        encrypt(container, 2, null, rcpt);
        decrypt(container, new KeyCrypto(priv), 0);
    }

    // Certificate recipient (CDoc2)

    @Test
    void certificateCdoc2() throws Exception {
        byte[] cert = readKey(EC384 + "-cert.der");
        byte[] priv = readKey(EC384 + "-priv.der");
        File container = new File(tempDir, "cert.cdoc2");
        Recipient rcpt = Recipient.makeCertificate("cert-label", cert);
        assertTrue(rcpt.isCertificate());

        encrypt(container, 2, null, rcpt);

        // Locate the lock by certificate, then decrypt with the private key
        CDocReader rdr = CDocReader.createReader(container.getAbsolutePath(), null, new KeyCrypto(priv), null);
        assertEquals(2, rdr.getVersion());
        long idx = rdr.getLockForCert(cert);
        assertTrue(idx >= 0, "no lock found for certificate");
        decryptWithReader(rdr, (int) idx);
    }

    // Certificate recipient (CDoc1 format)

    @Test
    void certificateCdoc1() throws Exception {
        byte[] cert = readKey(EC384 + "-cert.der");
        byte[] priv = readKey(EC384 + "-priv.der");
        File container = new File(tempDir, "cert-v1.cdoc");
        Recipient rcpt = Recipient.makeCertificate("v1-label", cert);

        encrypt(container, 1, null, rcpt);
        decrypt(container, new KeyCrypto(priv), 0);
    }

    // RSA certificate recipient (CDoc1, PKCS#1 v1.5 padding)

    @Test
    void rsaCertificateCdoc1() throws Exception {
        byte[] cert = readKey(RSA + "_cert.der");
        byte[] priv = readKey(RSA + "_priv.der");
        File container = new File(tempDir, "rsa-v1.cdoc");
        Recipient rcpt = Recipient.makeCertificate("rsa-v1-label", cert);

        encrypt(container, 1, null, rcpt);
        decrypt(container, new KeyCrypto(priv), 0);
    }

    // Multiple recipients in one container, each decryptable on its own

    @Test
    void multiRecipientCdoc2() throws Exception {
        String password = "multi-pw";
        byte[] ecPub = readKey(EC384 + "-pub.der");
        byte[] ecPriv = readKey(EC384 + "-priv.der");
        byte[] rsaPub = readKey(RSA + "_pub.der");
        byte[] rsaPriv = readKey(RSA + "_priv.der");
        File container = new File(tempDir, "multi.cdoc2");

        CDocWriter wrtr = CDocWriter.createWriter(2, container.getAbsolutePath(), null, new SecretCrypto(password.getBytes()), null);
        assertEquals(CDoc.OK, wrtr.addRecipient(Recipient.makeSymmetric("pw", 600000)));
        assertEquals(CDoc.OK, wrtr.addRecipient(Recipient.makePublicKey("ec", ecPub)));
        assertEquals(CDoc.OK, wrtr.addRecipient(Recipient.makePublicKey("rsa", rsaPub)));
        assertEquals(CDoc.OK, wrtr.beginEncryption());
        assertEquals(CDoc.OK, wrtr.addFile("payload.bin", PAYLOAD.length));
        assertEquals(CDoc.OK, wrtr.writeData(PAYLOAD));
        assertEquals(CDoc.OK, wrtr.finishEncryption());

        CDocReader rdr = CDocReader.createReader(container.getAbsolutePath(), null, null, null);
        LockVector locks = rdr.getLocks();
        assertEquals(3, locks.size());

        // Each recipient can decrypt independently
        decrypt(container, new SecretCrypto(password.getBytes()), 0);
        decrypt(container, new KeyCrypto(ecPriv), 1);
        decrypt(container, new KeyCrypto(rsaPriv), 2);
    }

    // Wrong key must fail, not crash

    @Test
    void wrongPasswordFails() throws Exception {
        File container = new File(tempDir, "wrongpw.cdoc2");
        encrypt(container, 2, new SecretCrypto("right".getBytes()), Recipient.makeSymmetric("pw", 600000));

        CDocReader rdr = CDocReader.createReader(container.getAbsolutePath(), null, new SecretCrypto("wrong".getBytes()), null);
        boolean failed = false;
        try {
            byte[] fmk = rdr.getFMK(0);
            failed = (rdr.beginDecryption(fmk) != CDoc.OK);
        } catch (CDocException e) {
            failed = true;
        }
        assertTrue(failed, "decryption with wrong password must fail");
    }

    // Helpers

    private static byte[] readKey(String name) throws Exception {
        return Files.readAllBytes(new File(DATA_DIR, name).toPath());
    }

    /** Encrypt the payload into a container with a single recipient. */
    private void encrypt(File container, int version, CryptoBackend crypto, Recipient rcpt) throws Exception {
        CDocWriter wrtr = CDocWriter.createWriter(version, container.getAbsolutePath(), null, crypto, null);
        assertEquals(CDoc.OK, wrtr.addRecipient(rcpt));
        assertEquals(CDoc.OK, wrtr.beginEncryption());
        assertEquals(CDoc.OK, wrtr.addFile("payload.bin", PAYLOAD.length));
        assertEquals(CDoc.OK, wrtr.writeData(PAYLOAD));
        assertEquals(CDoc.OK, wrtr.finishEncryption());
    }

    /** Decrypt the payload from a container using the lock at index lockIdx. */
    private void decrypt(File container, CryptoBackend crypto, int lockIdx) throws Exception {
        CDocReader rdr = CDocReader.createReader(container.getAbsolutePath(), null, crypto, null);
        decryptWithReader(rdr, lockIdx);
    }

    private void decryptWithReader(CDocReader rdr, int lockIdx) throws Exception {
        byte[] fmk = rdr.getFMK(lockIdx);
        assertEquals(CDoc.OK, rdr.beginDecryption(fmk));
        FileInfo fi = new FileInfo();
        assertEquals(CDoc.OK, rdr.nextFile(fi));
        assertEquals("payload.bin", fi.getName());
        byte[] data = new byte[(int) fi.getSize()];
        assertEquals(PAYLOAD.length, rdr.readData(data));
        assertArrayEquals(PAYLOAD, data);
        assertEquals(CDoc.END_OF_STREAM, rdr.nextFile(fi));
        assertEquals(CDoc.OK, rdr.finishDecryption());
    }

    /** Password/raw-key backend: supplies the secret for symmetric recipients. */
    private static class SecretCrypto extends CryptoBackend {
        private final byte[] secret;

        SecretCrypto(byte[] secret) {
            this.secret = secret;
        }

        @Override
        public long getSecret(DataBuffer dst, int idx) {
            dst.setData(secret);
            return CDoc.OK;
        }
    }

    /**
     * Private-key backend: performs ECDH1 key agreement (ECC recipients) and
     * RSA decryption (RSA recipients) with a PKCS#8 private key from
     * test/data.
     */
    private static class KeyCrypto extends CryptoBackend {
        private final PrivateKey privKey;
        private final boolean rsa;

        KeyCrypto(byte[] pkcs8) throws Exception {
            this.privKey = loadPrivateKey(pkcs8);
            this.rsa = privKey.getAlgorithm().equals("RSA");
        }

        private static PrivateKey loadPrivateKey(byte[] der) throws Exception {
            // test/data contains both PKCS#8 keys and bare SEC1 EC keys
            // (RFC 5915 ECPrivateKey). Wrap SEC1 into a PKCS#8 envelope so
            // that Java's KeyFactory can parse it.
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

        @Override
        public long deriveECDH1(DataBuffer dst, byte[] publicKey, int idx) throws CDocException {
            try {
                // libcdoc stores the ephemeral public key as a raw ANSI X9.62
                // uncompressed point (0x04 || X || Y), not as X.509 SPKI.
                if (publicKey.length < 1 || publicKey[0] != 4) return CDoc.CRYPTO_ERROR;
                int coordLen = (publicKey.length - 1) / 2;
                java.math.BigInteger x = new java.math.BigInteger(1, Arrays.copyOfRange(publicKey, 1, 1 + coordLen));
                java.math.BigInteger y = new java.math.BigInteger(1, Arrays.copyOfRange(publicKey, 1 + coordLen, publicKey.length));

                // Take the curve parameters from our own private key
                java.security.spec.ECParameterSpec params =
                        ((java.security.interfaces.ECPrivateKey) privKey).getParams();
                PublicKey peer = KeyFactory.getInstance("EC").generatePublic(
                        new java.security.spec.ECPublicKeySpec(new java.security.spec.ECPoint(x, y), params));

                KeyAgreement ka = KeyAgreement.getInstance("ECDH");
                ka.init(privKey);
                ka.doPhase(peer, true);
                dst.setData(ka.generateSecret());
                return CDoc.OK;
            } catch (Exception e) {
                return CDoc.CRYPTO_ERROR;
            }
        }

        @Override
        public long decryptRSA(DataBuffer dst, byte[] data, boolean oaep, int idx) throws CDocException {
            try {
                Cipher cipher;
                if (oaep) {
                    // CDoc2 uses OAEP with SHA-256 for both digests
                    cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                    cipher.init(Cipher.DECRYPT_MODE, privKey,
                            new OAEPParameterSpec("SHA-256", "MGF1",
                                    MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
                } else {
                    // CDoc1 uses PKCS#1 v1.5
                    cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher.init(Cipher.DECRYPT_MODE, privKey);
                }
                dst.setData(cipher.doFinal(data));
                return CDoc.OK;
            } catch (Exception e) {
                return CDoc.CRYPTO_ERROR;
            }
        }
    }
}
