package ee.ria.cdoc;

import java.io.File;
import java.security.SecureRandom;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CDocTest {

    @TempDir
    File tempDir;

    @BeforeAll
    static void loadLibrary() {
        // Uses the same resolution chain as CDocTool: -Dcdoc.library,
        // jni.properties baked into the jar, well-known build directories,
        // java.library.path.
        CDocTool.loadLibrary(null);
    }

    /**
     * Creates a password-based Recipient, validates it and checks the
     * automatically generated (machine-readable) lock label.
     */
    @Test
    void passwordRecipient() throws Exception {
        final String password = "JUnit test password";
        final String labelValue = "JUnit test";
        // Small iteration count to keep the test fast; any kdf_iter > 0
        // makes the recipient password-based ("pw").
        final int kdfIter = 1000;

        // Create a password-based recipient with empty label, so that the
        // lock label is generated automatically.
        Recipient rcpt = Recipient.makeSymmetric("", kdfIter);
        assertFalse(rcpt.isEmpty());
        assertTrue(rcpt.isSymmetric());
        assertEquals(kdfIter, rcpt.getKdf_iter());

        // A symmetric recipient without label or LABEL property is invalid
        assertFalse(rcpt.validate());
        // Provide the human-readable part of the generated label
        rcpt.setLabelValue("label", labelValue);
        assertTrue(rcpt.validate());

        // Write a container and read the generated label back from the lock
        File container = new File(tempDir, "test.cdoc2");
        TestCrypto crypto = new TestCrypto(password);
        CDocWriter wrtr = CDocWriter.createWriter(2, container.getAbsolutePath(), null, crypto, null);
        assertNotNull(wrtr);
        assertEquals(CDoc.OK, wrtr.addRecipient(rcpt));
        assertEquals(CDoc.OK, wrtr.beginEncryption());
        byte[] payload = {1, 2, 3, 4};
        assertEquals(CDoc.OK, wrtr.addFile("payload.bin", payload.length));
        assertEquals(CDoc.OK, wrtr.writeData(payload));
        assertEquals(CDoc.OK, wrtr.finishEncryption());

        CDocReader rdr = CDocReader.createReader(container.getAbsolutePath(), null, crypto, null);
        assertNotNull(rdr);
        assertEquals(2, rdr.getVersion());
        LockVector locks = rdr.getLocks();
        assertEquals(1, locks.size());
        Lock lock = locks.get(0);

        // The lock label must be the automatically generated machine-readable one
        String label = lock.getLabel();
        assertTrue(label.startsWith("data:"), "label should be machine-generated: " + label);

        Map<String, String> parsed = Lock.parseLabel(label);
        assertEquals("1", parsed.get("v"));
        assertEquals("pw", parsed.get("type"));
        assertEquals(labelValue, parsed.get("label"));

        // The same label must be produced by the std::map<string_view,...>
        // overload exposed through the SWIG Java typemap
        assertEquals(label, rcpt.getLabel(Map.of()));

        // Non-empty argument: extra values override the recipient's own
        // label parts with the same key, unknown keys are appended
        String overridden = rcpt.getLabel(Map.of("label", "overridden", "file", "payload.bin"));
        Map<String, String> parsedOverride = Lock.parseLabel(overridden);
        assertEquals("overridden", parsedOverride.get("label"));
        assertEquals("payload.bin", parsedOverride.get("file"));
        assertEquals("pw", parsedOverride.get("type"));
        // ...and must not mutate the recipient
        assertEquals(label, rcpt.getLabel(Map.of()));

        // Sanity check: the container is decryptable with the same password
        byte[] fmk = rdr.getFMK(0);
        assertEquals(CDoc.OK, rdr.beginDecryption(fmk));
        FileInfo fi = new FileInfo();
        long result = rdr.nextFile(fi);
        assertEquals(CDoc.OK, result);
        assertEquals("payload.bin", fi.getName());
        byte[] data = new byte[(int) fi.getSize()];
        assertEquals(payload.length, rdr.readData(data));
        assertArrayEquals(payload, data);
        assertEquals(CDoc.END_OF_STREAM, rdr.nextFile(fi));
        assertEquals(CDoc.OK, rdr.finishDecryption());
    }

    private static class TestCrypto extends CryptoBackend {
        private final byte[] secret;

        TestCrypto(String password) {
            this.secret = password.getBytes();
        }

        @Override
        public long getSecret(DataBuffer dst, int idx) {
            dst.setData(secret);
            return CDoc.OK;
        }
    }
}
