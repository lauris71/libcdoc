# Build instructions for Java

The Java example (`CDocTool`) compiles against the SWIG-generated Java
bindings produced by the libcdoc CMake build.

## Automatic build (recommended)

When the libcdoc project is configured with SWIG and a JDK available, the
example is built automatically as part of the default CMake build:

    cmake --preset macos
    cmake --build build/macos

This produces `examples/java/build/libs/CDocTool.jar`. Set
`-DLIBCDOC_BUILD_JAVA_EXAMPLE=OFF` to disable it.

## Manual build

First build the main CMake project so that the SWIG Java bindings and the
JNI library exist, then run the Gradle wrapper:

    ./gradlew jar

`build.gradle` locates the SWIG-generated sources automatically by scanning
the well-known CMake build directories (`build/<preset>/cdoc/java`). If your
build tree lives elsewhere, point the build at it explicitly:

    ./gradlew jar -PswigJavaDir=/path/to/build/cdoc/java -PjniLibDir=/path/to/build/cdoc

or with environment variables:

    LIBCDOC_SWIG_JAVA_DIR=/path/to/build/cdoc/java LIBCDOC_JNI_LIB_DIR=/path/to/build/cdoc ./gradlew jar

## Test

The example has JUnit 5 tests (in `src/test/java`) that run against the
compiled JNI library:

    ./gradlew test

The CMake-driven build runs the tests automatically (it invokes
`gradlew build`, which includes the `test` task).

## Run

    ./gradlew run

or directly:

    java -jar build/libs/CDocTool.jar

The JNI library built by the CMake project is located automatically. The
resolution order is:

1. `--library <file>` command line argument
2. `-Dcdoc.library=<file>` system property
3. `ee/ria/cdoc/jni.properties` baked into the jar by Gradle (records the
   JNI library directory at build time)
4. Well-known CMake build directories (`build/<preset>/cdoc`) relative to
   the working directory
5. `java.library.path` (set by `./gradlew run`, or pass
   `-Djava.library.path=/path/to/build/cdoc` to `java`)
