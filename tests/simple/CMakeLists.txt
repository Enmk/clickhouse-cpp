ADD_EXECUTABLE (simple-test
	main.cpp
)

TARGET_LINK_LIBRARIES (simple-test
	clickhouse-cpp-lib
)

if (WITH_OPENSSL)
    message("!!!!! OPENSSL_LIBRARIES : ${OPENSSL_LIBRARIES}")
    target_link_libraries(simple-test ${OPENSSL_LIBRARIES})
endif()
