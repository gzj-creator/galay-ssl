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
add_ssl_example(e1_echo_include include/e1_echo.cc)
add_ssl_example(e2_echo_include include/e2_echo.cc)
add_ssl_example(e3_custom_include include/e3_custom.cc)
add_ssl_example(e4_builder_include include/e4_builder.cc)

# import 版本（按模块开关自动启用）
if(BUILD_MODULE_EXAMPLES AND TARGET galay-ssl-modules)
    add_ssl_import_example(e1_echo_import import/e1_echo.cc)
    add_ssl_import_example(e2_echo_import import/e2_echo.cc)
    add_ssl_import_example(e3_custom_import import/e3_custom.cc)
    add_ssl_import_example(e4_builder_import import/e4_builder.cc)
else()
    message(STATUS "Import examples are skipped (BUILD_MODULE_EXAMPLES=OFF or galay-ssl-modules unavailable)")
endif()
