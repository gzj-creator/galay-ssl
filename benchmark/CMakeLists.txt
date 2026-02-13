if(BUILD_BENCHMARKS)
    # SSL 性能测试
    add_executable(B1-SslBenchServer B1-SslBenchServer.cc)
    target_link_libraries(B1-SslBenchServer PRIVATE galay-ssl)

    add_executable(B1-SslBenchClient B1-SslBenchClient.cc SslStats.cc)
    target_link_libraries(B1-SslBenchClient PRIVATE galay-ssl)
endif()
