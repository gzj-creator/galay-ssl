if(BUILD_TESTS)
    # SSL Socket 测试
    add_executable(T1-SslSocketTest T1-SslSocketTest.cc)
    target_link_libraries(T1-SslSocketTest PRIVATE galay-ssl)

    # 复制测试证书到 bin 目录和 build 根目录
    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/certs
         DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/certs
         DESTINATION ${CMAKE_BINARY_DIR})
endif()
