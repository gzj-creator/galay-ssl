function(add_ssl_example target_name source_file)
    add_executable(${target_name} ${source_file})
    target_link_libraries(${target_name} PRIVATE galay-ssl)
endfunction()

function(add_ssl_import_example target_name source_file)
    add_executable(${target_name} ${source_file})
    target_link_libraries(${target_name} PRIVATE galay-ssl-modules)
    set_target_properties(${target_name} PROPERTIES CXX_SCAN_FOR_MODULES ON)
endfunction()

# include 版本
add_ssl_example(E1-SslEchoServer-Include include/E1-ssl_echo_server.cc)
add_ssl_example(E2-SslClient-Include include/E2-ssl_client.cc)
add_ssl_example(E3-SslCustomStateMachine-Include include/E3-ssl_custom_state_machine.cc)
add_ssl_example(E4-SslBuilderProtocol-Include include/E4-ssl_builder_protocol.cc)

# import 版本（按模块开关自动启用）
if(BUILD_MODULE_EXAMPLES AND TARGET galay-ssl-modules)
    add_ssl_import_example(E1-SslEchoServer-Import import/E1-ssl_echo_server.cc)
    add_ssl_import_example(E2-SslClient-Import import/E2-ssl_client.cc)
    add_ssl_import_example(E3-SslCustomStateMachine-Import import/E3-ssl_custom_state_machine.cc)
    add_ssl_import_example(E4-SslBuilderProtocol-Import import/E4-ssl_builder_protocol.cc)
else()
    message(STATUS "Import examples are skipped (BUILD_MODULE_EXAMPLES=OFF or galay-ssl-modules unavailable)")
endif()
