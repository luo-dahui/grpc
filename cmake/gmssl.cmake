
if(gRPC_SSL_PROVIDER STREQUAL "module")
  message(STATUS "gRPC_GMSSL_PROVIDER is module===========")

  set(THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party)
  # set(_gRPC_SSL_INCLUDE_DIR ${THIRD_PARTY_DIR}/gmssl/include)
  # set(_gRPC_SSL_LIBRARIES tassl tacrypto)

  # add_subdirectory(${THIRD_PARTY_DIR}/gmssl)

  # if(TARGET ssl)
  #   # link_directories(${THIRD_PARTY_DIR}/gmssl/lib)
  #   set(_gRPC_SSL_INCLUDE_DIR ${THIRD_PARTY_DIR}/gmssl/include)
  #   set(_gRPC_SSL_LIBRARIES tassl tacrypto)
  #   if(gRPC_INSTALL AND _gRPC_INSTALL_SUPPORTED_FROM_MODULE)
  #     install(TARGETS tassl tacrypto EXPORT gRPCTargets
  #       RUNTIME DESTINATION ${gRPC_INSTALL_BINDIR}
  #       LIBRARY DESTINATION ${gRPC_INSTALL_LIBDIR}
  #       ARCHIVE DESTINATION ${gRPC_INSTALL_LIBDIR})
  #   endif()
  # endif()

  
  include_directories(${THIRD_PARTY_DIR}/gmssl/include)
  link_directories(${THIRD_PARTY_DIR}/gmssl/lib)
  set(_gRPC_SSL_INCLUDE_DIR ${THIRD_PARTY_DIR}/gmssl/include)

  # link_libraries(tacrypto tassl) 
  set(_gRPC_SSL_LIB_DIR ${THIRD_PARTY_DIR}/gmssl/lib)
  set(_gRPC_SSL_LIBRARIES ${_gRPC_SSL_LIB_DIR}/libtassl.a 
    ${_gRPC_SSL_LIB_DIR}/libtacrypto.a )

endif()
