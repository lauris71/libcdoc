# Introduction to libcdoc

The libcdoc project is an open-source C++ library designed for handling CDoc (Cryptographic Document) containers, a format used for secure document encryption. 
While CDoc containers are a component of secure digital workflows, libcdoc specifically focuses on the encryption and decryption of these containers rather 
than digital signatures.

CDoc containers are utilized in Estonia for secure document exchange, especially in contexts where confidentiality is critical. The libcdoc library enables 
applications to create, parse, and decrypt encrypted CDoc containers, ensuring secure access to sensitive content.

## Key Features

- **Cross-Platform Support:** The library is compatible with Windows, macOS, and Linux for desktop environments, as well as iOS and Android for mobile platforms.
- **Support for CDoc Versions:** Handles CDoc 1.0 and 1.1 formats ([CDoc 1.0](https://www.id.ee/wp-content/uploads/2020/02/SK-CDOC-1.0-20120625_EN.pdf), [CDoc 1.1](https://www.ria.ee/sites/default/files/content-editors/EID/cdoc.pdf)) as well as CDoc 2.0 ([CDoc 2.0 Specification](https://open-eid.github.io/CDOC2/2.0/)).
- **Future-Proof Design:** Includes support for workflows based on current and upcoming standard changes ([CDoc 2.0 Specification](https://open-eid.github.io/CDOC2/2.0/)), ensuring compatibility with evolving requirements.
- **Encryption Support:** Provides functionality for encrypting and decrypting documents securely, including both online and offline decryption workflows.
- **Extended Encryption Schemes:** Supports password-based encryption/decryption schemes, Smart-ID and Mobile-ID based encryption and decryption (documents can be encrypted for a personal code - the key is split across at least two key-share servers and all shares are required to decrypt - and decrypted after a Smart-ID or Mobile-ID authentication, see the [Tool](tool.md#smart-id-and-mobile-id-key-shares) examples), as well as ID-card/smart-card encryption and other additional hardware security tokens.
- **Multi-Recipient Encryption:** Supports encrypting files for multiple recipients using various encryption methods, including public key, password-based, and hardware token-based schemes.
- **Integration with eID Systems:** Can be used alongside other components in the Estonian ID-card infrastructure, although it does not handle digital signatures.
- **Multi-Language Support:** The library is written in C++ and provides Java and C# bindings using SWIG, enabling cross-platform usage in various programming environments.
- **Command-Line Tool:** Includes the `cdoc-tool` utility for encrypting, decrypting, and managing CDoc containers via the command line, refer to the [Tool](tool.md) document.

## Use Cases

- Applications requiring secure encrypted document handling.
- Services involving confidential document exchange.
- Integration with digital identity systems for secure communication.

## Licensing and Contributions

libcdoc is licensed under the LGPL, allowing it to be used in both open-source and proprietary software. Contributions are welcome via pull requests on GitHub.

This library plays a key role in enabling confidential digital document workflows in Estonia and can serve as a model for implementing similar secure container 
formats in other systems.

## Library Architecture

The libcdoc library is structured around modular and extensible components that handle various aspects of CDoc container processing. For a detailed explanation of the library's architecture, refer to the [Overview](overview.md) document.
