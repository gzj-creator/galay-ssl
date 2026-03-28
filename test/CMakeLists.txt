function(add_ssl_test target_name source_file)
    add_executable(${target_name} ${source_file})
    target_link_libraries(${target_name} PRIVATE galay-ssl)
    add_test(NAME ${target_name} COMMAND ${target_name})
    set_tests_properties(${target_name} PROPERTIES WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endfunction()

add_ssl_test(T1-SslSocketTest T1-ssl_socket_test.cc)
add_ssl_test(T2-SslLoopbackSmoke T2-ssl_loopback_smoke.cc)
add_ssl_test(T3-SslSingleShotSemantics T3-ssl_single_shot_semantics.cc)
add_ssl_test(T4-SslStateMachineSurface T4-ssl_state_machine_surface.cc)
add_ssl_test(T5-SslRecvSendStateMachine T5-ssl_recv_send_state_machine.cc)
add_ssl_test(T6-SslCustomStateMachine T6-ssl_custom_state_machine.cc)
add_ssl_test(T7-SslBuilderSurface T7-ssl_builder_surface.cc)
add_ssl_test(T8-SslBuilderProtocol T8-ssl_builder_protocol.cc)
add_ssl_test(T9-SslSequenceBaseErrorBridge T9-ssl_sequence_base_error_bridge.cc)

# 复制测试证书到 bin 目录和 build 根目录
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/certs
     DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/certs
     DESTINATION ${CMAKE_BINARY_DIR})
