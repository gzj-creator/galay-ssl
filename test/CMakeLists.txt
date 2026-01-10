if(BUILD_TESTS)
    # SSL Socket 测试
    add_executable(test_ssl_socket test_ssl_socket.cc)
    target_link_libraries(test_ssl_socket PRIVATE galay-ssl)

    # 复制测试证书到 bin 目录和 build 根目录
    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/certs
         DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/certs
         DESTINATION ${CMAKE_BINARY_DIR})
endif()
