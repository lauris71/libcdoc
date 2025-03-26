set(SCHEMAS
    schema/recipients.fbs
    schema/header.fbs
)

set(PUBLIC_HEADERS
    CDoc.h
    CDocReader.h
    CDocWriter.h
    Configuration.h
    Exports.h
    Io.h
    Recipient.h
    Lock.h
    CryptoBackend.h
    NetworkBackend.h
    PKCS11Backend.h
    ILogger.h
    ConsoleLogger.h
)

add_library(cdoc_ver INTERFACE)
target_compile_definitions(cdoc_ver INTERFACE
    VERSION_STR="${VERSION}"
    $<$<PLATFORM_ID:Windows>:VERSION=${PROJECT_VERSION_MAJOR},${PROJECT_VERSION_MINOR},${PROJECT_VERSION_PATCH},${BUILD_NUMBER}>
    $<$<PLATFORM_ID:Windows>:TARGET_NAME="$<TARGET_PROPERTY:NAME>">
    $<$<PLATFORM_ID:Windows>:$<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>:APP>>
)
target_sources(cdoc_ver INTERFACE libcdoc.rc)

add_library(cdoc
    ${PUBLIC_HEADERS}
    CDoc.cpp
    Io.cpp
    Recipient.cpp
    Lock.cpp
    Configuration.cpp
    CryptoBackend.cpp
    NetworkBackend.cpp
    PKCS11Backend.cpp
    LogEngine.cpp
    $<$<PLATFORM_ID:Windows>:WinBackend.cpp>
    Certificate.cpp Certificate.h
    Crypto.cpp Crypto.h
    Tar.cpp Tar.h
    ZStream.h
    # Internal
    Utils.cpp Utils.h
    CDoc1Reader.cpp CDoc1Reader.h
    CDoc1Writer.cpp CDoc1Writer.h
    CDoc2Reader.cpp CDoc2Reader.h
    CDoc2Writer.cpp CDoc2Writer.h
    DDocReader.cpp DDocReader.h
    DDocWriter.cpp DDocWriter.h
    KeyShares.cpp KeyShares.h
    XmlReader.cpp XmlReader.h
    XmlWriter.cpp XmlWriter.h
    RcptInfo.h
    ToolConf.h
    CDoc2.h
    Wrapper.h
    utils/memory.h
)
set_target_properties(cdoc PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "${PUBLIC_HEADERS}"
    FRAMEWORK_VERSION 1
    FRAMEWORK "${FRAMEWORK}"
    MACOSX_FRAMEWORK_IDENTIFIER "ee.ria.cdoc"
    MACOSX_RPATH YES
    POSITION_INDEPENDENT_CODE YES
)
target_include_directories(cdoc PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
)

if(NOT BUILD_SHARED_LIBS)
    target_compile_definitions(cdoc PUBLIC cdoc_STATIC)
endif()
target_link_libraries(cdoc PRIVATE
    OpenSSL::SSL
    LibXml2::LibXml2
    ZLIB::ZLIB
    $<$<BOOL:BUILD_SHARED_LIBS>:cdoc_ver>
    $<TARGET_NAME_IF_EXISTS:flatbuffers::flatbuffers>
    #$<TARGET_NAME_IF_EXISTS:flatbuffers::flatbuffers_shared>
)

if(BUILD_TOOLS)
    add_executable(cdoc-tool cdoc-tool.cpp CDocCipher.cpp)
    target_include_directories(cdoc-tool PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(cdoc-tool cdoc_ver cdoc OpenSSL::SSL)
    set_target_properties(cdoc-tool PROPERTIES
        INSTALL_RPATH $<$<PLATFORM_ID:Darwin>:@executable_path/../lib>
    )
    install(TARGETS cdoc-tool DESTINATION ${CMAKE_INSTALL_BINDIR})
    #install( FILES ${CMAKE_CURRENT_BINARY_DIR}/cdoc-tool.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 )
endif()

if(WIN32)
    list(APPEND PUBLIC_HEADERS WinBackend.h)
    add_compile_definitions(UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(cdoc PRIVATE Crypt32 NCrypt cryptui)
endif()

foreach(SCHEMA ${SCHEMAS})
    get_filename_component(stem ${SCHEMA} NAME_WE)
    get_filename_component(name ${SCHEMA} NAME)
    set(GENERATED_INCLUDE ${CMAKE_CURRENT_BINARY_DIR}/${stem}_generated.h)
    add_custom_command(
        OUTPUT ${GENERATED_INCLUDE}
        COMMENT "Compiling flatbuffer for ${name}"
        COMMAND flatbuffers::flatc
                --cpp
                --scoped-enums
                -o ${CMAKE_CURRENT_BINARY_DIR}
                -I ${CMAKE_CURRENT_SOURCE_DIR}
                ${SCHEMA}
        DEPENDS flatbuffers::flatc ${SCHEMA}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_sources(cdoc PRIVATE ${SCHEMA} ${GENERATED_INCLUDE})
endforeach()

if(SWIG_FOUND)
    include(${SWIG_USE_FILE})
    include_directories(${CMAKE_CURRENT_SOURCE_DIR})
    set_property(SOURCE ../libcdoc.i PROPERTY CPLUSPLUS ON)
    if(JAVA_INCLUDE_PATH)
        file(COPY CDocException.java DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/java)
        file(COPY IStreamSource.java DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/java)
        set(CMAKE_SWIG_FLAGS -package ee.ria.cdoc)
        swig_add_library(cdoc_java LANGUAGE java SOURCES ../libcdoc.i OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/java)
        target_include_directories(cdoc_java PRIVATE ${JAVA_INCLUDE_PATH} $<$<BOOL:${JAVA_INCLUDE_PATH2}>:${JAVA_INCLUDE_PATH2}>)
        target_link_libraries(cdoc_java cdoc_ver cdoc)
        set_target_properties(cdoc_java PROPERTIES
            INSTALL_RPATH $<$<PLATFORM_ID:Darwin>:/Library/Frameworks>
            SWIG_COMPILE_DEFINITIONS $<$<PLATFORM_ID:Windows>:SWIGWIN>
        )
        #install(TARGETS cdoc_java DESTINATION $<IF:$<PLATFORM_ID:Darwin>,/Library/Java/Extensions,${CMAKE_INSTALL_LIBDIR}>) # FIXME: build mac packages
        install(TARGETS cdoc_java DESTINATION ${CMAKE_INSTALL_LIBDIR})
        install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/java/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ee/ria/cdoc FILES_MATCHING PATTERN "*.java")
        if(WIN32)
            install(FILES $<TARGET_PDB_FILE:cdoc_java> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
        endif()
        if(Java_Development_FOUND)
            file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/glob_java_files.cmake "
            file(GLOB_RECURSE JAVA_COMPILE_FILELISTS \${JAVA_DIR}/*.java)
            file(WRITE \${CMAKE_CURRENT_BINARY_DIR}/java_file_list \"\")
            foreach(JAVA_FILE \${JAVA_COMPILE_FILELISTS})
                file(APPEND \${CMAKE_CURRENT_BINARY_DIR}/java_file_list \"\${JAVA_FILE}\n\")
            endforeach()
            ")
            add_custom_command(TARGET cdoc_java POST_BUILD
                COMMAND ${CMAKE_COMMAND} -D JAVA_DIR=${CMAKE_CURRENT_BINARY_DIR}/java -P ${CMAKE_CURRENT_BINARY_DIR}/glob_java_files.cmake
                BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/java_file_list
            )
            include(UseJava)
            set(CMAKE_JAVA_COMPILE_FLAGS --release 11)
            add_jar(cdoc_jar SOURCES @${CMAKE_CURRENT_BINARY_DIR}/java_file_list OUTPUT_NAME cdoc)
            #install_jar(cdoc_jar DESTINATION $<IF:$<PLATFORM_ID:Darwin>,/Library/Java/Extensions,${CMAKE_INSTALL_DATADIR}/libcdoc>)
            install_jar(cdoc_jar DESTINATION ${CMAKE_INSTALL_DATADIR}/libcdoc)
        endif()
    endif()
    if(Python3_FOUND)
	# TODO: Fix Python wrapping
    endif()

    set(CMAKE_SWIG_FLAGS -namespace cdoc)
    swig_add_library(cdoc_csharp LANGUAGE csharp SOURCES ../libcdoc.i OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/csharp)
    target_link_libraries(cdoc_csharp cdoc_ver cdoc)
    set_target_properties(cdoc_csharp PROPERTIES
        SWIG_COMPILE_DEFINITIONS $<$<PLATFORM_ID:Windows>:SWIGWIN>
        INSTALL_RPATH $<$<PLATFORM_ID:Darwin>:/Library/Frameworks>
        PREFIX "${CMAKE_SHARED_LIBRARY_PREFIX}"
    )
    install(TARGETS cdoc_csharp DESTINATION ${CMAKE_INSTALL_LIBDIR})
    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/csharp/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cdoc_csharp FILES_MATCHING PATTERN "*.cs")
    if(WIN32)
        install(FILES $<TARGET_PDB_FILE:cdoc_csharp> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
    endif()
endif()

if(APPLE)
    set(MODULE_LIST ${PUBLIC_HEADERS})
    list(TRANSFORM MODULE_LIST PREPEND "  header \"")
    list(TRANSFORM MODULE_LIST APPEND "\"")
    list(JOIN MODULE_LIST "\n" MODULE_LIST)
    set(MODULE_MAP ${CMAKE_BINARY_DIR}/module.modulemap)
    file(WRITE ${MODULE_MAP} "framework module cdoc {
${MODULE_LIST}
  export *
  requires cplusplus
}")
    target_sources(cdoc PRIVATE ${MODULE_MAP})
    set_source_files_properties(${MODULE_MAP} PROPERTIES MACOSX_PACKAGE_LOCATION Modules)
    if(IOS)
        add_custom_command(TARGET cdoc POST_BUILD
            COMMAND /usr/libexec/PlistBuddy -c "Add :MinimumOSVersion string ${CMAKE_OSX_DEPLOYMENT_TARGET}" $<TARGET_FILE_DIR:cdoc>/Info.plist
        )
    endif()
endif()

install(TARGETS cdoc
    EXPORT cdocExport
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    RESOURCE DESTINATION ${CDOC_CONFIG_DIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cdoc
    FRAMEWORK DESTINATION ${FRAMEWORK_DESTINATION}
)
if(WIN32 AND BUILD_SHARED_LIBS)
    install(FILES $<TARGET_PDB_FILE:cdoc> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
endif()

if(NOT ANDROID)
    install(EXPORT cdocExport
        FILE cdoc-config.cmake
        NAMESPACE cdoc::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cdoc
    )
    include(CMakePackageConfigHelpers)
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/cdoc-config-version.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY AnyNewerVersion
    )
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/cdoc-config-version.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cdoc
    )
endif()

#install( FILES ${CMAKE_CURRENT_BINARY_DIR}/libcdoc.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig )
