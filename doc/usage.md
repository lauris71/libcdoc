# Basic libcdoc Library Usage

This document provides an overview of how to use the **libcdoc** library for encryption and decryption workflows.

---

## CDOC1 vs. CDOC2 Formats

The **libcdoc** library supports two container formats:

- **CDOC1**: A legacy format suitable for compatibility with older systems. It provides basic encryption and decryption functionality.
- **CDOC2**: A modern format with enhanced security features, such as key-server integration and improved cryptographic algorithms.

---

## Common

The **libcdoc** library is built around three main components that work together to handle encryption, decryption, and key management. It is compatible with Windows, macOS, and Linux for desktop environments, as well as iOS and Android for mobile platforms:

1. **libcdoc::CryptoBackend**  
   Handles cryptographic operations such as key management, encryption, and decryption. This is the core component responsible for all cryptographic logic.

2. **libcdoc::NetworkBackend**  
   Manages interactions with external key-servers. This component is optional and is only required if your workflow involves fetching or storing keys on a remote server.

3. **libcdoc::Configuration**  
   Provides configuration parameters, such as key-server URLs and certificates, to the `libcdoc::NetworkBackend`. This component ensures that the `libcdoc::NetworkBackend` has the necessary information to communicate with external servers.

In addition to these backends, the library provides two key classes for working with CDOC containers:

- **libcdoc::CDocWriter**: Used for creating encrypted CDOC containers. It supports both CDOC1 and CDOC2 formats, allowing you to specify the desired version during the encryption process.
- **libcdoc::CDocReader**: Used for reading and decrypting CDOC containers. It can automatically detect whether a container is in CDOC1 or CDOC2 format.

These components interact with each other to enable secure encryption and decryption workflows. The following diagram illustrates their relationships:

```plaintext
+-------------------+       +-------------------+
|   CryptoBackend   |<----->|   NetworkBackend  |
| (Handles keys,    |       | (Optional: Key    |
| encryption/decrypt|       | server interaction|
+-------------------+       +-------------------+
          ^                           ^
          |                           |
          +---------------------------+
                        |
                        v
              +-------------------+
              |   Configuration   |
              | (Provides key     |
              | server parameters)|
              +-------------------+
```

Most methods in the library return a `libcdoc::result_t` status value, which can indicate the following:

- **OK (= 0)**: Indicates success.
- **Positive value**: For read and write methods, this indicates success and the number of bytes read or written.
- **END_OF_STREAM (= 1)**: For `nextFile` methods, this indicates the end of the file list in a multi-file source.
- **Any error value (< -1)**: Indicates failure.

---

## Encryption

Encryption is managed by the `libcdoc::CDocWriter` object.

### Workflow Diagram

The following diagram illustrates the encryption workflow:

```plaintext
+-------------------+       +-------------------+       +-------------------+
|   Data Source     |       |   CryptoBackend   |       |   NetworkBackend  |
| (e.g., file data) |       | (Handles keys,    |       | (Optional: Key    |
|                   |       | encryption logic) |       | server interaction|
+-------------------+       +-------------------+       +-------------------+
          |                           |                           |
          v                           v                           v
      +---------------------------------------------------------------+
      |                           CDocWriter                          |
      | (Manages encryption process, writes encrypted container file) |
      +---------------------------------------------------------------+
                                      |
                                      v
                            +-------------------+
                            |   Output File     |
                            | (Encrypted CDOC)  |
                            +-------------------+
```

---

### CryptoBackend

To use encryption, you must create or implement a `libcdoc::CryptoBackend` class. The default implementation is sufficient for public key encryption schemes. For symmetric key encryption, you must implement at least one of the following methods:

#### `getSecret`

```cpp
int getSecret(std::vector<uint8_t>& dst, unsigned int idx)
```

This method copies either the password (for PBKDF-based keys) or the plain AES key into the `dst` vector. While simple, this method may expose the password or key in memory.

#### `getKeyMaterial`

```cpp
int getKeyMaterial(std::vector<uint8_t>& dst, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, unsigned int idx)
```

This method returns the key material for a symmetric key (either password or plain key) derivation. The default implementation calls `getSecret` and performs PBKDF2_SHA256 if the key is password-based.

#### `extractHKDF`

```cpp
result_t extractHKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, unsigned int idx)
```

This method calculates the Key Encryption Key (KEK) pre-master from a symmetric key (either password or key-based). The default implementation calls `getKeyMaterial` and performs a local HKDF extract.

---

### NetworkBackend

If you intend to use a key-server, you must subclass `libcdoc::NetworkBackend` and implement the following methods:

#### `getClientTLSCertificate`

```cpp
int getClientTLSCertificate(std::vector<uint8_t>& dst)
```

Returns the client's TLS certificate for authentication with the key-server.

#### `getPeerTLSCertificates`

```cpp
int getPeerTLSCertificates(std::vector<std::vector<uint8_t>> &dst)
```

Returns the list of acceptable peer certificates for the key-server. Returning empty list disables TLS peer certificate check in debug builds but results in CONFIGURATION_ERROR in release builds.

#### `signTLS`

```cpp
int signTLS(std::vector<uint8_t>& dst, libcdoc::CryptoBackend::HashAlgorithm algorithm, const std::vector<uint8_t> &digest)
```

Signs the provided digest for TLS authentication.

In addition to implementing `libcdoc::NetworkBackend`, you must also instantiate a `libcdoc::Configuration` subclass.

---

### Configuration

The `libcdoc::Configuration` class is required to retrieve key-server parameters. You must subclass it and implement the following method:

#### `getValue`

```cpp
std::string getValue(std::string_view domain, std::string_view param)
```

Returns the configuration value for a given domain/parameter combination. For key-servers:

- **Domain**: The key-server ID.
- **Param**: `KEYSERVER_SEND_URL`.

---

### CDocWriter

The `libcdoc::CDocWriter` object is created using one of the following static methods:

```cpp
libcdoc::CDocWriter* createWriter(int version, libcdoc::DataConsumer* dst, bool take_ownership, libcdoc::Configuration* conf, libcdoc::CryptoBackend* crypto, libcdoc::NetworkBackend* network);
libcdoc::CDocWriter* createWriter(int version, std::ostream& ofs, libcdoc::Configuration* conf, libcdoc::CryptoBackend* crypto, libcdoc::NetworkBackend* network);
libcdoc::CDocWriter* createWriter(int version, const std::string& path, libcdoc::Configuration* conf, libcdoc::CryptoBackend* crypto, libcdoc::NetworkBackend* network);
```

- **`dst`, `ofs`, `path`**: Input stream to read file content.
- **`take_ownership`**: Indicates if `libcdoc::CDocWriter` takes ownership of `src` object.
- **`version`**: Specifies the file format (1 for CDOC version 1, 2 for CDOC version 2).
- **`crypto`**: A `libcdoc::CryptoBackend` instance (required).
- **`network`**: A `libcdoc::NetworkBackend` instance (optional, for key-server use) or `nullptr`.
- **`conf`**: A `libcdoc::Configuration` instance (optional, for key-server use) or `nullptr`.

The `libcdoc::CDocWriter` does not take ownership of `crypto`, `network` and `conf` objects, so they should be deleted by caller.

#### Workflow

1. **Add Recipients**  
   Add one or more recipients using:

   ```cpp
   int addRecipient(const Recipient& rcpt);
   ```

2. **Begin Encryption**  
   Start the encryption process:

   ```cpp
   int beginEncryption();
   ```

3. **Write Files**  
   Add files and write their data:

   ```cpp
   int addFile(const std::string& name, size_t size);
   int64_t writeData(const uint8_t* src, size_t size);
   ```

4. **Finish Encryption**  
   Finalize the encryption process:

   ```cpp
   int finishEncryption();
   ```

---

### Implementation Example

```cpp
struct MyBackend : public libcdoc::CryptoBackend {
    /* Only needed for symmetric keys */
    int getSecret(std::vector<uint8_t>& dst, unsigned int idx) override final {
        /* Write secret to dst */
    }
};

/* In the data processing method */
MyBackend crypto;

libcdoc::CDocWriter *writer = createWriter(version, cdoc_filename, nullptr, &crypto, nullptr);

/* For each recipient */
writer->addRecipient(myrcpt);
writer->beginEncryption();

/* For each file */
writer->addFile(filename, -1);
writer->writeData(data, data_size);

/* Finalize encryption */
writer->finishEncryption();

delete writer;
```

---

## Decryption

Decryption is managed by the `libcdoc::CDocReader` object.

### Workflow Diagram

The following diagram illustrates the decryption workflow:

```plaintext
+-------------------+       +-------------------+       +-------------------+
|   Input File      |       |   CryptoBackend   |       |   NetworkBackend  |
| (Encrypted CDOC)  |       | (Handles keys,    |       | (Optional: Key    |
|                   |       | decryption logic) |       | server interaction|
+-------------------+       +-------------------+       +-------------------+
          |                           |                           |
          v                           v                           v
      +---------------------------------------------------------------+
      |                           CDocReader                          |
      | (Manages decryption process, reads encrypted container file)  |
      +---------------------------------------------------------------+
                                      |
                                      v
                            +-------------------+
                            |   Output Files    |
                            | (Decrypted data)  |
                            +-------------------+
```

---

### CryptoBackend

Create or implement a CryptoBackend class. To decrypt all lock types, at least the following methods have to be implemented:

```cpp
int deriveECDH1(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, unsigned int idx)
```

Derives a shared secret from document's public key and recipient's private key by using ECDH1 algorithm.

```cpp
int decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t>& data, bool oaep, unsigned int idx)
```

Decrypts data using RSA private key.

Also one of the symmetric key methods listed in encryption section for symmetric key support.

---

### NetworkBackend

It has to be implemented and supplied if server-based capsules are needed.

---

### Configuration

To decrypt server capsules, configuration has to contain the value of the following entry (domain is key-server id as in encryption):

- KEYSERVER_FETCH_URL

---

### CDocReader

To determine whether a file or `libcdoc::DataSource` is a valid CDOC container, use:

```cpp
int libcdoc::CDocReader::getCDocFileVersion(const std::string& path);
int libcdoc::CDocReader::getCDocFileVersion(libcdoc::DataSource *src);
```

Both methods return the container version (1 or 2) or a negative value if the file/source is invalid.

The `libcdoc::CDocReader` has to be created with one of the following static methods:

```cpp
libcdoc::CDocReader* createReader(libcdoc::DataSource* src, bool take_ownership, libcdoc::Configuration* conf, libcdoc::CryptoBackend* crypto, libcdoc::NetworkBackend* network);
libcdoc::CDocReader* createReader(const std::string& path, libcdoc::Configuration* conf, libcdoc::CryptoBackend* crypto, libcdoc::NetworkBackend* network);
libcdoc::CDocReader* createReader(std::istream& ifs, libcdoc::Configuration* conf, libcdoc::CryptoBackend* crypto, libcdoc::NetworkBackend* network);
```

- **`src`, `path`, `ifs`**: Input stream to read file content.
- **`take_ownership`**: Indicates if `libcdoc::CDocReader` takes ownership of `src` object.
- **`crypto`**: A `libcdoc::CryptoBackend` instance (required when case decrypting) or `nullptr`.
- **`network`**: A `libcdoc::NetworkBackend` instance (optional, for key-server use) or `nullptr`.
- **`conf`**: A `libcdoc::Configuration` instance (optional, for key-server use) or `nullptr`.

The `libcdoc::CDocReader` does not take ownership of `crypto`, `network` and `conf` objects, so they should be deleted by caller.

#### Workflow

The list of locks in file can be obtained by method:

```cpp
const std::vector<Lock>& getLocks()
```

The order of locks is the same as in CDoc container and the 0-based index is used to refer to the lock in decryption methods.

As a convenience method, a public-key lock can be looked up by a certificate (DER-encoded):

```cpp
result_t getLockForCert(const std::vector<uint8_t>& cert)
```

Returns the index of a lock that can be opened by the private key of the certificate, or negative number if not found.

Once the correct lock is chosen, the FMK (File Master Key) of the container has to be obtained:

```cpp
result_t getFMK(std::vector<uint8_t>& fmk, unsigned int lock_idx)
```

Depending on the lock type the method calls appropriate methods of CryptoBackend (and NetworkBackend) implementation to obtain and decrypt FMK.

After that the FMK can be used to start the encryption:

```cpp
result_t beginDecryption(const std::vector<uint8_t>& fmk)
```

Individual files can be read by nextFile method:

```cpp
result_t nextFile(std::string& name, int64_t& size)
```

The method returns the name and size of the next file in encrypted stream, or END_OF_STREAM if there are no more files. Due to the structure
of CDoc container, files have to be processed sequentially - there is no way to rewind the stream.
The name returned depends on the configured filename policy (see [Filename handling](filenames.md)). By default (*strict* mode) only
conformant names are returned - a container with non-conformant names fails with DATA_FORMAT_ERROR - and suspicious names come back
repaired. With `FILENAME_MODE` set to `lenient` the name is returned exactly as stored in the encrypted stream. Applications that write
returned names to disk should flatten and confine them first; the `libcdoc::FileListConsumer` sink does this automatically.

The actual decrypted data can be read with method:

```cpp
result_t readData(uint8_t *dst, size_t size)
```

This reads the data from current file.

When all files are read, the finalizer has to be called:

```cpp
result_t finishDecryption()
```

The decrypted data should *not be used* before successful finalization because it performs the final check of data integrity. If it
fails, the data should be assumed incomplete or corrupted. The finalizer must be called after the extraction loop **in all cases** -
including when the loop stopped on a local error (I/O failure, name policy violation): it drains the payload, verifies the integrity
and its result takes precedence over any local error (a failed integrity check is always the main error).

---

### Implementation Example

Below is an example of how to implement decryption using the `libcdoc::CDocReader` object and a custom `libcdoc::CryptoBackend` subclass:

```cpp
struct MyBackend : public libcdoc::CryptoBackend {
    /* Elliptic curves */
    result_t deriveECDH1(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, unsigned int idx) override final {
        /* Derive shared secret and write to dst */
    }
    /* RSA */
    result_t decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t>& data, bool oaep, unsigned int idx) override final {
        /* Decrypt data and write to dst */
    }
    /* Only needed for symmetric keys */
    int getSecret(std::vector<uint8_t>& dst, unsigned int idx) override final {
        /* Write secret to dst */
    }
};

/* In the data processing method */
MyBackend crypto;

libcdoc::CDocReader* reader = createReader(cdoc_filename, nullptr, &crypto, nullptr);

/* Get locks */
auto locks = reader->getLocks();

/* Choose a lock that you have a key for, then decrypt FMK */
std::vector<uint8_t> fmk;
reader->getFMK(fmk, lock_idx);

/* Start decryption */
reader->beginDecryption(fmk);
std::string name;
int64_t size;
while(reader->nextFile(name, size) == libcdoc::OK) {
    /* Allocate data buffer etc... */
    reader->readData(buffer, size);
}

/* Finalize decryption */
reader->finishDecryption();

delete reader;
```

This example demonstrates how to:
1. Subclass `libcdoc::CryptoBackend` to implement the required decryption methods (`deriveECDH1` and `decryptRSA`).
2. Create a `libcdoc::CDocReader` instance and use it to process an encrypted CDOC container.
3. Retrieve locks, decrypt the File Master Key (FMK), and read the decrypted files.

---
