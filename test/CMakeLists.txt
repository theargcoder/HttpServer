function(add_httpserver_executable name src)
  add_executable(${name} ${src})
  target_link_libraries(${name} PRIVATE HttpServer Boost::unit_test_framework)
  target_compile_definitions(${name} PRIVATE BOOST_TEST_DYN_LINK)
endfunction()

function(add_httpserver_test name)
  add_test(NAME ${name} COMMAND ${name})
endfunction()

# ------------------------------------------------------------
# Targets & Tests Setup
# ------------------------------------------------------------

add_httpserver_executable(test_basic test.cpp)

add_httpserver_test(test_basic)
