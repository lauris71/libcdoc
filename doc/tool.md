# libcdoc Tool Usage

The **libcdoc** library includes a command-line tool, **cdoc-tool** (or **cdoc-tool.exe** on Windows), which can be used to encrypt and decrypt files, as well as view the locks in an encrypted container. The tool is compatible with Windows, macOS, and Linux platforms.

---

## Encryption

The general syntax for encrypting files for one or more recipients is the following:

```bash
cdoc-tool encrypt --rcpt RECIPIENT [--rcpt...] [-v1] [--genlabel]
    [--library PKCS11_LIBRARY]
    [--server ID URL(s)]
    [--accept SERVER_CERT_FILENAME]
    --out OUTPUTFILE
    FILE1 [FILE2 FILE3... FILEn]
```

To re-encrypt a file for a different recipient(s) or with a different encryption method, use the **re-encrypt** switch instead of **encrypt**. For that both decryption and encryption options have to be specified.

### Options

- `--v1` - generates CDOC ver. 1 format container instead of CDOC ver. 2 container. The option can be used only when encrypting with public-key certificate 
(see [Recipients](#Recipients)). In all other cases, CDOC ver. 2 format container is created. Tool gives an error if the option is used with any other encryption method.

- `--genlabel` - causes machine-readable label generation for the lock instead of using label provided with `--rcpt` option. The machine-readable label follows the 
format described in [5.1.2.1 KeyLabel recommendations](https://open-eid.github.io/CDOC2/2.0/02_protocol_and_cryptography_spec/ch03_container_format/#keylabel-recommendations) 
chapter of *CDOC2 container format* specification, and differs depending on selected encryption method.

- `--library` - path to the PKCS11 library that handles smart-card related operations. The option is needed only in MacOS and Linux when `p11sk` or `p11pk` encryption 
method is used (see [Recipients](#Recipients)). In Windows the tool uses API provided by Windows. In all other cases the option is ignored.

- `--server ID URL(s)` - specifies a key or share server. The recipient key will be stored in server instead of container. For key server the URL is either fetch 
or send URL. For share server it is comma-separated list of share server URLs.

- `--accept SERVER_CERT_FILENAME` - path to server's TLS certificate file. The certificate must be in DER format. Needed only if a key or shared server is used, i.e. 
`--server` option is specified.

- `--out OUTPUTFILE` - CDOC file name to be created. This option is mandatory. If the file name is provided without path then the file is created in current working 
directory.

- `FILE` - one or more files to be encrypted. At least one file must be provided.

### Recipients

One or more recipients must be specified, each with its own encryption method.

| Form | Description |
| ---    | ---         |
| `[label]:cert:CERTIFICATE_HEX` | Encryption public-key from certificate. The certificate must be provided as hex-encoded string |
| `[label]:skey:SECRET_KEY_HEX` | Symmetric encryption with AES key. The key must be provided as hex-encoded string |
| `[label]:pkey:SECRET_KEY_HEX` | Encryption with public-key. The key must be provided as hex-encoded string |
| `[label]:pfkey:PUB_KEY_FILE` | Encryption with public-key. The key (**secp384r1** or **secp256r1**) is read from the DER-encoded file. |
| `[label]:pw:PASSWORD` | Encryption with derive key using PWBKDF |
| `[label]:p11sk:SLOT:[PIN]:[PKCS11 ID]:[PKCS11 LABEL]` | Encryption with AES key from PKCS11 module |
| `[label]:p11pk:SLOT:[PIN]:[PKCS11 ID]:[PKCS11 LABEL]` | Encryption with public key from PKCS11 module |
| `[label]:share:ID` | use key share server with given ID (personal code) |

If the `label` is omitted then the `--genlabel` option must be specified at command-line. Otherwise, the tool generates an error. If both, `label` and `--genlabel` 
option are provided then depending on encryption method, the `label` may be ignored, but may be also used a part of machine-readable label, like in encrypting with 
symmetric key and password case. Refer [Appendix D](https://open-eid.github.io/CDOC2/2.0/02_protocol_and_cryptography_spec/keylabel_field/) section of 
*CDOC2 container format* specification for examples of machine-readable key-labels.
If '?' is used in place of PIN or PASSWORD the tool asks for the value interactively.

### Examples

1. **Encrypt a file with a password**  
   Encrypt the file `abc.txt` with the password `Test123`. The resulting container is `abc.txt-pw.cdoc`.

   ```bash
   ./cdoc-tool encrypt --rcpt Test:pw:Test123 --out abc.txt-pw.cdoc abc.txt
   ```

2. **Encrypt a file with a public key from an ID card**  
   Encrypt the file `abc.txt` using a public key from an Estonian ID card. The resulting container is `abc.txt-p11pk.cdoc`. To use the ID card a PKCS11 library has to be specified, the exact location depends on the operating system and installed software.

   ```bash
   ./cdoc-tool encrypt --rcpt :p11pk:0:::Isikutuvastus --genlabel --out abc.txt-p11pk.cdoc --library /opt/homebrew/lib/opensc-pkcs11.so abc.txt
   ```

3. **Encrypt a file with a public key from a file**  
   Encrypt the file `abc.txt` using a public key from the file `ec-secp384r1-pub.der`. The resulting container is `abc.txt-pfkey.cdoc`.

   ```bash
   ./cdoc-tool encrypt --rcpt :pfkey:ec-secp384r1-pub.der --genlabel --out abc.txt-pfkey.cdoc abc.txt
   ```

4. **Encrypt a file with an AES key**  
   Encrypt the file `abc.txt` using an AES key provided via the command line. The resulting container is `abc.txt-aes.cdoc`.

   ```bash
   ./cdoc-tool encrypt --rcpt Test:skey:E165475C6D8B9DD0B696EE2A37D7176DFDF4D7B510406648E70BAE8E80493E5E --genlabel --out abc.txt-aes.cdoc abc.txt
   ```

5. **Encrypt a file with a public key from an ID card and use key server**  
   Encrypt the file `abc.txt` using a public key from an Estonian ID card and use the RIA key server. The resulting container is `abc.txt-ks.cdoc`.

   ```bash
   ./cdoc-tool encrypt --rcpt Test:p11pk:0:::Isikutuvastus --library /opt/homebrew/lib/opensc-pkcs11.so --server 00000000-0000-0000-0000-000000000000 https://cdoc2.id.ee:8443 --accept keyserver-cert.der --out abc.txt-ks.cdoc abc.txt
   ```

---

## Decryption

The syntax for decrypting an encrypted file is the following:

```bash
cdoc-tool decrypt OPTIONS FILE [OUTPUT_DIR]
```

### Options

Following options are supported:

- `--label LABEL` - CDOC container's lock label. Either the label or label's index must be provided.
- `--label_idx INDEX` - CDOC container's lock 1-based label index. Either the label or label's index must be provided.
- `--slot SLOT` - PKCS11 slot number. Usually 0.
- `--password PASSWORD` - lock's password if the file was encrypted with password. Use '?' to ask for the password interactively.
- `--secret SECRET` - secret phrase (AES key) if the file was encrypted with symmetric key. Use '?' to ask for the secret interactively.
- `--pin PIN` - PKCS11 (smart-card's) pin code. Use '?' to ask for the pin interactively.
- `--key-id` - PKCS11 key ID.
- `--key-label` - PKCS11 key label.
- `--library PKCS11_LIBRARY` - path to the PKCS11 library. Same as in encryption case.
- `--server ID URL(s)` - specifies a key or share server. Same as in encryption case.
- `--accept SERVER_CERT_FILENAME` - path to server's TLS certificate file. Same as in encryption case.
- `--auth-server URL` - Smart-ID / Mobile-ID authentication server. Required when decrypting a container encrypted for a key-share recipient (see [Smart-ID and Mobile-ID](#smart-id-and-mobile-id-key-shares)).
- `--rp-server URL` - relying party server used in Smart-ID / Mobile-ID authentication. Required for key-share recipients.
- `--phone NUMBER` - phone number in international format (starting with `+`) selecting Mobile-ID authentication. If not specified, Smart-ID is used.
- `FILE` - encrypted file to be decrypted.
- `OUTPUT_DIR` - output directory where the files are decrypted. If not specified then current working directory is used. If there is already a file with same name 
then it is overwritten.

### Examples

1. **Decrypt a file with a password**  
   Decrypt the file `abc.txt-pw.cdoc` using the key with label `Test` and password `Test123`.

   ```bash
   ./cdoc-tool decrypt --label Test --password Test123 abc.txt-pw.cdoc
   ```

2. **Decrypt a file with an ID card**  
   Decrypt the file `abc.txt-p11pk.cdoc` using the key from lock `1` and an Estonian ID card with PIN code `1234`.

   ```bash
   ./cdoc-tool decrypt --label_idx 1 --pin 1234 --slot 0 --key-label Isikutuvastus --library /opt/homebrew/lib/opensc-pkcs11.so abc.txt-p11pk.cdoc
   ```

3. **Decrypt a file with an ID card and use key server**  
   Decrypt the file `abc.txt-ks.cdoc` using the key with label `Test` and a private key from an ID card, using the RIA key server.

   ```bash
   ./cdoc-tool decrypt --library /opt/homebrew/lib/opensc-pkcs11.so --server 00000000-0000-0000-0000-000000000000 https://cdoc2.id.ee:8444 --accept keyserver-cert.der --label Test --slot 0 --pin 1234 --key-label Isikutuvastus abc.txt-ks.cdoc out
   ```

---

## Smart-ID and Mobile-ID (key shares)

Documents can be encrypted for a person's **personal code** without having
their certificate: the encryption key is **split** into shares which are
stored on **at least two** *share servers* (`[label]:share:ID` recipient,
see [Recipients](#Recipients)). The shares are not replicas: the key is
divided between the servers (XOR-based split) and **all shares are needed**
to regenerate it. Decryption authenticates the person with **Smart-ID** or
**Mobile-ID** and collects the shares back.

The following options are used with key-share recipients (in addition to
`--server` for the share server(s) themselves):

- `--server ID URL[,URL...]` - share server(s) used to store and fetch the key shares. At least two comma-separated URLs are required: the key is split between them (the shares are not replicas) and all shares are needed to decrypt.
- `--auth-server URL` - Smart-ID / Mobile-ID authentication server (needed for decryption).
- `--rp-server URL` - relying party server used in the authentication session (needed for decryption).
- `--phone NUMBER` - Mobile-ID phone number in international format. When omitted, Smart-ID is used.
- `--accept FILENAME` - TLS certificate of the servers (DER); may be repeated per server.

During decryption the tool displays a **verification code** in the terminal
and waits until the authentication is confirmed in the Smart-ID or Mobile-ID
application.

### Examples

1. **Encrypt for a Smart-ID recipient**
   Encrypt `document.pdf` for the person with personal code `30303039903`,
   storing the key shares on `share.example`:

   ```bash
   ./cdoc-tool encrypt --rcpt 'Test:share:30303039903' \
       --server share.example https://share1.example:8443,https://share2.example:8443 \
       --out document.pdf.cdoc document.pdf
   ```

2. **Decrypt with Smart-ID**
   The verification code is shown in the terminal; confirm it in the
   Smart-ID application:

   ```bash
   ./cdoc-tool decrypt --label Test \
       --server share.example https://share1.example:8443,https://share2.example:8443 \
       --auth-server https://sid.example:8443 \
       --rp-server https://rp.example:8443 \
       document.pdf.cdoc
   ```

3. **Decrypt with Mobile-ID**
   Same as above with `--phone` selecting Mobile-ID authentication:

   ```bash
   ./cdoc-tool decrypt --label Test \
       --server share.example https://share1.example:8443,https://share2.example:8443 \
       --auth-server https://mid.example:8443 \
       --rp-server https://rp.example:8443 \
       --phone +37269930366 \
       document.pdf.cdoc
   ```

---

## Re-encryption

Re-encrypting a file decrypts it and then encrypts again for new recipients on-the-fly. This avoids writing the decrypted data to the disk.

The syntax for re-encrypting an encrypted file is the following:

```bash
cdoc-tool re-encrypt OPTIONS INPUT_FILE --out OUTPUTFILE
```

### Options

Both decryption and encryption options are supported with the following constraints:

- Output directory, if specified, is ignored.
- Only single URL can be specified for server. Thus, if re-encrypting by using capsule server base lock to another capsule server recipient, a JSON configuration with several server URLs should be used (see [JSON configuration file](#json-configuration-file)).
- Only single PKCS11 library can be specified. Thus it is not possible to re-encrypt from one harware token to another, unless they use the same PKCS11 library.
- All original locks (recipients) will be removed from container and replaced with new ones.

---

## JSON configuration file

The network-related settings can also be expressed as a JSON document
(`libcdoc::JSONConfiguration`, which `ToolConf` implements). This is useful
when embedding libcdoc and when several server URLs are needed (see
[Re-encryption](#re-encryption)). The document is a single JSON object:

- root-level entries are root settings, e.g. `AUTH_SERVER`, `RP_SERVER`,
  `PHONE_NUMBER`, `SHARE_SIGNER` (`SMART_ID` or `MOBILE_ID`)
- nested objects are configuration domains: a server `ID` maps to its
  settings, e.g. `SHARE_SERVER_URLS` (a JSON array of share server URLs) or
  `KEYSERVER_SEND_URL`/`KEYSERVER_FETCH_URL` for a key server
- string values are used as-is; other JSON values (arrays, numbers) are
  passed in their JSON form

```json
{
    "AUTH_SERVER": "https://sid.example:8443",
    "RP_SERVER": "https://rp.example:8443",
    "PHONE_NUMBER": "+37269930366",
    "SHARE_SIGNER": "SMART_ID",
    "share.example": {
        "SHARE_SERVER_URLS": ["https://share1.example:8443", "https://share2.example:8443"]
    },
    "key.example": {
        "KEYSERVER_SEND_URL": "https://key.example/send",
        "KEYSERVER_FETCH_URL": "https://key.example/fetch"
    }
}
```

The example corresponds to the command line `--server share.example
https://share1.example:8443,https://share2.example:8443 --auth-server
https://sid.example:8443 --rp-server https://rp.example:8443 --phone
+37269930366`. See [Usage](usage.md#configuration) for how the
`libcdoc::Configuration` interface exposes these values to the library.

---

## Viewing Locks

To view the locks in a container, use the following syntax:

```bash
cdoc-tool locks FILE
```

This command does not have any options. The only argument is the encrypted container file whose locks will be displayed.

### Example

Display the locks of the file `abc.txt-aes.cdoc`:

```bash
./cdoc-tool locks abc.txt-aes.cdoc
```
