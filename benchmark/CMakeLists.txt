if(BUILD_BENCHMARKS)
    # SSL 性能测试
    add_executable(b1_server b1_server.cc)
    target_link_libraries(b1_server PRIVATE galay-ssl)

    add_executable(b1_client b1_client.cc ssl_stats.cc)
    target_link_libraries(b1_client PRIVATE galay-ssl)
endif()
