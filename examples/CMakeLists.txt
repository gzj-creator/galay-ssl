# examples CMakeLists.txt

# E1-SslEchoServer
add_executable(E1-SslEchoServer E1-SslEchoServer.cc)
target_link_libraries(E1-SslEchoServer PRIVATE galay-ssl)

# E2-SslClient
add_executable(E2-SslClient E2-SslClient.cc)
target_link_libraries(E2-SslClient PRIVATE galay-ssl)
