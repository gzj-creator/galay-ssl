if(BUILD_BENCHMARKS)
    # SSL 性能测试
    add_executable(bench_ssl_server bench_ssl_server.cc)
    target_link_libraries(bench_ssl_server PRIVATE galay-ssl)

    add_executable(bench_ssl_client bench_ssl_client.cc)
    target_link_libraries(bench_ssl_client PRIVATE galay-ssl)
endif()
