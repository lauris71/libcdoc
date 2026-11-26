# Overview of libcdoc

The libcdoc project is an open-source C++ library designed for handling CDoc (Cryptographic Document) containers, a format used for secure document encryption. While CDoc containers are a component of secure digital workflows, libcdoc specifically focuses on the encryption and decryption of these containers rather than digital signatures.

CDoc containers are utilized in Estonia for secure document exchange, especially in contexts where confidentiality is critical. The libcdoc library enables applications to create, parse, and decrypt encrypted CDoc containers, ensuring secure access to sensitive content.

## Key Features

- **Support for CDoc Versions**: Handles CDoc 1.0 and 1.1 formats (CDoc 1.0, CDoc 1.1) as well as CDoc 2.0 ([CDoc 2.0 Specification](https://open-eid.github.io/CDOC2/2.0/)).
- **Future-Proof Design**: Includes support for workflows based on current and upcoming standard changes ([CDoc 2.0 Specification](https://open-eid.github.io/CDOC2/2.0/)), ensuring compatibility with evolving requirements.
- **Encryption Support**: Provides functionality for encrypting and decrypting documents securely, including both online and offline decryption workflows.
- **Extended Encryption Schemes**: Supports password-based encryption/decryption schemes, Smart-ID and Mobile-ID based encryption and decryption (documents can be encrypted for a personal code - the key is split across at least two key-share servers and all shares are required to decrypt - and decrypted after a Smart-ID or Mobile-ID authentication, see the [Tool](tool.md#smart-id-and-mobile-id-key-shares) examples), as well as ID-card/smartcard encryption and other additional hardware security tokens.
- **Integration with eID Systems**: Can be used alongside other components in the Estonian ID-card infrastructure, although it does not handle digital signatures.
- **Cross-Platform Support:** The library is compatible with Windows, macOS, and Linux for desktop environments, as well as iOS and Android for mobile platforms.
- **Multi-Language Support:** Offers Java and C# bindings using SWIG for cross-platform development.
- **Command-Line Tool:** Includes the `cdoc-tool` utility for managing CDoc containers via the command line, refer to the [Tool](tool.md) document.

For detailed workflows, refer to the [Usage](usage.md) document.

## Library Architecture

The libcdoc library is structured around modular and extensible components that handle various aspects of CDoc container processing. The design emphasizes maintainability and flexibility to accommodate evolving standards and security requirements.

### Core Components

- **CDocReader/CDocWriter:** Responsible for reading and writing CDoc 1.x and 2.0 containers. It supports parsing XML-based metadata and managing encrypted payloads.
- **Encryption Engine:** Handles encryption and decryption using cryptographic libraries such as OpenSSL. It supports a variety of schemes, including public key encryption (smartcards, ID-cards, Mobile-ID, Smart-ID), symmetric password-based encryption, and hybrid encryption models.
- **Recipient Management:** Implements recipient-specific key wrapping and metadata handling for multi-recipient encrypted documents.
- **Workflow Support:** Enables both online and offline workflows, supporting scenarios where keys are available via connected tokens or remote signing/encryption services.
- **Standards Abstraction:** Provides an abstraction layer for handling differences between CDoc versions and upcoming specification changes.

### Extensibility

The architecture is designed to allow easy integration of new encryption backends and recipient schemes. For instance, support for emerging mobile and cloud-based identity systems can be added without restructuring core functionality.

### Multi-Language Support with SWIG

The libcdoc library uses **SWIG (Simplified Wrapper and Interface Generator)** to generate bindings for Java and C#. This allows developers to use the library in applications written in these languages without needing to write custom wrappers manually.

- **Java Wrappers:** SWIG generates Java bindings, enabling seamless integration of libcdoc into Java-based applications. This is particularly useful for enterprise systems, Android applications, and cross-platform mobile development.
- **C# Wrappers:** SWIG also generates C# bindings, making libcdoc accessible to .NET developers for use in Windows desktop applications or cross-platform .NET Core projects.

The library's compatibility with iOS and Android platforms ensures that developers can integrate libcdoc into mobile applications, enabling secure document workflows on mobile devices. The use of SWIG ensures that the library's core functionality remains consistent across all supported languages and platforms, reducing maintenance overhead and improving interoperability.

## Interoperability

libcdoc maintains strong compatibility with other components in the Estonian eID ecosystem and adheres closely to official specifications to ensure interoperability across different platforms and implementations.

This architectural foundation ensures that libcdoc remains a reliable and future-ready library for secure document encryption in both governmental and private sector applications.