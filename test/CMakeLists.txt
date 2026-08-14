add_executable(unittests
    libcdoc_boost.cpp
    libcdoc_live_boost.cpp
    ../cdoc/Crypto.cpp
    ../cdoc/KeyShares.cpp
    ../cdoc/Tar.cpp
    ../cdoc/XmlReader.cpp
    ../cdoc/Utils.cpp
)

target_compile_definitions(unittests PRIVATE HAS_KEYSHARES)

# The live SID/MID tests (libcdoc_live_boost.cpp) run against the RIA test
# servers with TLS certificate checks disabled until the RIA cert-pinning
# infrastructure is ready - propagate the flag so the test skips cleanly
# in default builds.
if(LIBCDOC_ALLOW_INSECURE_TLS)
    target_compile_definitions(unittests PRIVATE LIBCDOC_ALLOW_INSECURE_TLS)
endif()

target_link_libraries(unittests
    OpenSSL::SSL
    LibXml2::LibXml2
    cdoc
    Boost::unit_test_framework
)

add_test(NAME runtest
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/unittests --build_info=YES --logger=HRF,all,stdout
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/test
)
if(WIN32)
    set_tests_properties(runtest PROPERTIES
        ENVIRONMENT "PATH=$<TARGET_FILE_DIR:cdoc>;$ENV{PATH}"
    )
endif()

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} -C $<CONFIG> --output-on-failure DEPENDS unittests)
