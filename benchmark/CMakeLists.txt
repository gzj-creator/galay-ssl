if(BUILD_BENCHMARKS)
    # SSL 性能测试
    add_executable(B1-SslBenchServer B1-ssl_bench_server.cc)
    target_link_libraries(B1-SslBenchServer PRIVATE galay-ssl)

    add_executable(B1-SslBenchClient B1-ssl_bench_client.cc SslStats.cc)
    target_link_libraries(B1-SslBenchClient PRIVATE galay-ssl)
endif()
