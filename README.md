# libcdoc

A encryption/decryption library for CDoc container format.

## Features

- CDoc1 encryption by certificate (RSA/ECC)
- CDoc1 decryption (PKSC11/NCrypt private key)
- CDoc2 encryption by public key (RSA/ECC)
- CDoc2 decryption by private key (PKSC11/NCrypt)
- CDoc2 key-server support
- CDoc2 symmetric encryption (AES)
- CDoc2 symmetric encryption (password-based)

For more information refer [doc/intro.md](doc/intro.md) document.

## Building
[![Build Status](https://github.com/open-eid/libcdoc/workflows/CI/badge.svg?branch=master)](https://github.com/open-eid/libcdoc/actions)

### Ubuntu, Fedora

1. Install dependencies

        # Ubuntu
        sudo apt install cmake libxml2-dev zlib1g-dev
        # Fedora
        sudo dnf install cmake gcc-c++ libtool-ltdl-devel libxml2-devel openssl-devel zlib-devel

	* flatbuffers - required
	* doxygen - Optional, for API documentation
	* libboost-test-dev - Optional, for unit tests
	* swig - Optional, for C# and Java bindings
	* openjdk-17-jdk-headless - Optional, for Java bindings

2. Fetch the source

        git clone https://github.com/open-eid/libcdoc.git
        cd libcdoc

3. Configure

        cmake -B build -S .

4. Build

        cmake --build build

5. Install

        sudo cmake --build build --target install

### macOS

1. Install dependencies from
	* [XCode](https://developer.apple.com/xcode/) - For macOS/iOS development
	* [CMake](https://cmake.org)
	* [Homebrew](https://brew.sh)

2. Fetch the source

        git clone https://github.com/open-eid/libcdoc.git
        cd libdcdoc

3. Install dependencies

        brew install flatbuffers openssl opensc

 	* flatbuffers - Required
	* openssl - Required, version 3.0.0 or later
	* opensc - Optional, for smart-card operations
	* doxygen - Optional, for API documentation
	* boost - Optional, for unit tests
	* swig - Optional, for C# and Java bindings
	* openjdk - Optional, for Java bindings

4. Configure

        cmake -B build -S .

5. Build

        cmake --build build

6. Install

        sudo cmake --build build --target install

### Windows

1. Install dependencies and necessary tools from
	* [Visual Studio Community 2022](https://www.visualstudio.com/downloads/)
	* [CMake](http://www.cmake.org)
	* [vcpkg](https://vcpkg.io/)
	* [Swig](http://swig.org/download.html) - Optional, for C# and Java bindings
	* [Doxygen](https://www.doxygen.nl/download.html) - Optional, for generating documentation
	* [Java](https://www.oracle.com/java/technologies/downloads/) - Optional, for Java bindings

2. Open desired Visual Studio tools command prompt:
	* x64 Native Tool Command Prompt
	* ARM64 Native Tool Command Prompt
	* Or some cross compile combination with target host type

3. Fetch the source

        git clone https://github.com/open-eid/libcdoc.git
        cd libcdoc

4. Configure, build and install

        .\build.ps1

    `build.ps1` drives the `windows` CMake preset with vcpkg. If neither the `-vcpkg`
    parameter nor the `VCPKG_ROOT` environment variable points to a vcpkg checkout, one is
    cloned automatically. By default it builds the x64 Debug and RelWithDebInfo
    configurations. Common options:

        .\build.ps1 -platform arm64          # target ARM64
        .\build.ps1 -RunTests                # build and run the unit tests
        .\build.ps1 -installdir C:\libcdoc   # install after building
        .\build.ps1 -generator "Visual Studio 17 2022"   # use another CMake generator
