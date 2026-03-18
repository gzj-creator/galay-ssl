if(BUILD_TESTS)
    # SSL Socket 测试
    add_executable(T1-SslSocketTest T1-ssl_socket_test.cc)
    target_link_libraries(T1-SslSocketTest PRIVATE galay-ssl)

    add_executable(T2-SslLoopbackSmoke T2-ssl_loopback_smoke.cc)
    target_link_libraries(T2-SslLoopbackSmoke PRIVATE galay-ssl)

    add_executable(T3-SslSingleShotSemantics T3-ssl_single_shot_semantics.cc)
    target_link_libraries(T3-SslSingleShotSemantics PRIVATE galay-ssl)

    add_executable(T4-SslStateMachineSurface T4-ssl_state_machine_surface.cc)
    target_link_libraries(T4-SslStateMachineSurface PRIVATE galay-ssl)

    add_executable(T5-SslRecvSendStateMachine T5-ssl_recv_send_state_machine.cc)
    target_link_libraries(T5-SslRecvSendStateMachine PRIVATE galay-ssl)

    add_executable(T6-SslCustomStateMachine T6-ssl_custom_state_machine.cc)
    target_link_libraries(T6-SslCustomStateMachine PRIVATE galay-ssl)

    add_executable(T7-SslBuilderSurface T7-ssl_builder_surface.cc)
    target_link_libraries(T7-SslBuilderSurface PRIVATE galay-ssl)

    add_executable(T8-SslBuilderProtocol T8-ssl_builder_protocol.cc)
    target_link_libraries(T8-SslBuilderProtocol PRIVATE galay-ssl)

    # 复制测试证书到 bin 目录和 build 根目录
    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/certs
         DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/certs
         DESTINATION ${CMAKE_BINARY_DIR})
endif()
