ADD_EXECUTABLE (simple-test
	main.cpp
)

TARGET_LINK_LIBRARIES (simple-test
	clickhouse-cpp-lib
)

if (WITH_OPENSSL)
    target_link_libraries(simple-test OpenSSL::SSL)
endif()
