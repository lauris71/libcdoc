# libcdoc architecture

## Error handling

Most libcdoc methods return the result of the operation as `result_t` value (signed 64-bit integer). The meaning of the resiult is the following:
- for `read` methods 0 or positive value marks success and gives the actual number of bytes read. If the value is less than the requested size, end of file/stream is reached.
- for `nextFile` method value `END_OF_STREAM` (1) marks that there are no more sub-streams in data object.
- For all other methods `OK` (0) marks success of an operation
- Any negative value means error

Most object can return the more detailed textual description of error by one of the methods:

    std::string getLastErrorStr(result_t code)

or

    std::string getLastErrorStr()

The textual error is guaranteed to be correct only if these methods are called immediately after the failed operation and (for the first method) the error code is the one returned by the operation.

## Configuration

As libcdoc is not a stand-alone application but library, it's configuration system is meant to be integrated with a host application.
To achieve this, libcdoc reads all configurable data from an instance of [`Configuration`] object.

The Configuration superclass contains only single virtual method:

```cpp
std::string getValue(std::string_view domain, std::string_view param)
```

that is used throughout libcdoc to read relevant settings. Applications can create implementations of this method that read settings in arbitrary data sources (e.g. XML files, JSON files, registry database etc.)

The `domain` argument marks the logical group of configuration values. For example, for key-servers the `domain` is the server id. Empty domain represents a root-level value.

Under `domain` the individual parameters can be read by `param` argument, e.g. key upload and download urls (KEYSERVER_SEND_URL and KEYSERVER_FETCH_URL).

Filename handling is controlled by root-level parameters as well: `ALLOW_PATHNAMES` (write policy of the file source) and `FILENAME_MODE`
(reader name policy: `strict`, `safe` or `lenient`). See [Filename handling](filenames.md) for the complete rules.

### JSONConfiguration

For the convenience, if single global configuration file is sufficient, there is also `JSONConfiguration` class that reads parameter values from a JSON file. The file has to contain single JSON object with key/value pairs representing either configuration domains (if value is JSON object) or root-level values (if the type is anything else). Inside domain the key/value pairs represent individual settings.

If the value is not directly representable as string it is passed to library as serialized JSON.

Example JSON configuration file:

    {
        "SHARE_SIGNER" : "SMART_ID",
        "SMART_ID" : {
            "BASE_URL" : "https://sid.demo.sk.ee/smart-id-rp/v2",
            "RP_UUID" : "00000000-0000-0000-0000-000000000000",
            "RP_NAME" : "DEMO"
        }
    }

Here `SHARE_SIGNER` is root-level configuration value representing the method for signing key shares (`SMART_ID`).

The second `SMART_ID` represents configuration domain for SmartID signer, containing relevant parameters to establish the authentication session.

## Input-output objects

To simplify writing language wrappers libcdoc implements several input and output object classes. Using these is not mandatory, CDoc documents can be also read and written to standard c++ streams or ordinary files.

### DataConsumer

An abstract base class of output objects.

### DataSource

An abstract base class of input objects.

### MultiDataConsumer

A DataConsumer subclass that supports writing sequentially into multiple named streams.

### MultiDataSource

A DataSource subclass that supports reading sequentially from multiple named streams.

## CryptoBackend

All potentially sensitive cryptographic operations are performed by `CryptoBackend` class. This allows an application to keep tight control over the execution and prevent the leakage of sensitive information into memory.

Normally `CryptoBackend` is not needed for encrypting with public key and thus can be omitted for such cases. It has to be provided for all decryption operations and for encryption with symmetric keys/passwords.

`CryptoBackend` has some front-end implementations of certain cryptographic procedures. But the handling of actual keys (e.g. asking user for password, performing decryption on hardware token etc.) has to be performed by application-implemented subclass.

### Low-level virtual methods

These are the lowest level parts of each cryptographic method (EC, RSA and symmetric key). Implementing these is sufficient to get the these methods to work, but applications may choose to implement higher level methods instead for security reasons.

#### result_t deriveECDH1(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, unsigned int idx)

Derives shared secret from EC private key and given ephemereal public key (Elliptic-curve Diffie–Hellman algorithm). The index marks the relative index (0-based) of the lock capsule in CDoc container.

#### result_t decryptRSA(std::vector<uint8_t>& dst, const std::vector<uint8_t>& data, bool oaep, unsigned int idx)

Decrypt data with RSA private key.

#### result_t getSecret(std::vector<uint8_t>& dst, unsigned int idx)

Fetch either AES symmetric key or user password for key derivation.

### High-level virtual methods

Implementing these allows application to sidestep libcdoc default implementation of cryptographic primitives. This may be preferable for security (to minimize the risk of leaking secrets to memory) or techincal reasons (e.g. to allow performing the full key derivation inside hardware security module).

#### result_t random(std::vector<uint8_t>& dst, unsigned int size)

Allows subclasses to use their own implementation of (pseudo)random number generator. The library default implementation uses OpenSSL generator.

#### result_t deriveConcatKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::string &digest, const std::vector<uint8_t> &algorithm_id, const std::vector<uint8_t> &party_uinfo, const std::vector<uint8_t> &party_vinfo, unsigned int idx);

Derive key by EC ConcatKDF algorithm

#### deriveHMACExtract(std::vector<uint8_t>& dst, const std::vector<uint8_t> &public_key, const std::vector<uint8_t> &salt, unsigned int idx)

Derive key by EC HMAC algorithm

#### result_t getKeyMaterial(std::vector<uint8_t>& dst, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, unsigned int idx)

Get key material from secret. Does nothing with actual symmetric key, use PBKDF2_SHA256 for password.

#### result_t extractHKDF(std::vector<uint8_t>& dst, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& pw_salt, int32_t kdf_iter, unsigned int idx)

Extract key from symmetric key material with HKDF algorithm.

For convenience libcdoc contains also PKCS11 and WinCrypt subclasses.

### PKCS11Backend

`PKCS11Backend` implements the CryptoBackend methods using PKCS11 interface. Still the actual loading of key from token has to be done by application (i.e. by `PKCS11Backend` subclass).

The application has to implement single method:

```cpp
result_t connectToKey(int idx, bool priv)
```
that should locate the correct slot, get pin and then ask `PKCS11Backend` to use the relevant key (of the lock `idx` of CDoc container) for subsequent encryption or decryption by calling:

```cpp
result_t useSecretKey(int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label)
```

```cpp
result_t usePrivateKey(int slot, const std::vector<uint8_t>& pin, const std::vector<uint8_t>& id, const std::string& label)
```

### WinBackend

`WinBackend` is similar to `PKCS11Backend` but instead of PKCS11 library it uses WinCrypto methods. Like in `PKCS11Backend` the subclass has to implement:

```cpp
result_t connectToKey(int idx, bool priv)
```

which should then call the actual key loading method:

```cpp
result_t useKey(const std::string& name, const std::string& pin)
```
