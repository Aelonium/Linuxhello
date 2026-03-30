cmake_minimum_required(VERSION 3.16)

# ── Test: test_crypto ─────────────────────────────────────────────────────────
add_executable(test_crypto
    test_crypto.c
    ../src/crypto/challenge.c
    ../src/crypto/tpm_ops.c
    ../src/storage/storage.c
)
target_include_directories(test_crypto PRIVATE
    ../src/common
    ../src/crypto
    ../src/storage
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(test_crypto PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(HAVE_TPM2)
    target_include_directories(test_crypto PRIVATE ${TSS2_ESYS_INCLUDE_DIRS})
    target_link_libraries(test_crypto PRIVATE
        ${TSS2_ESYS_LIBRARIES} ${TSS2_RC_LIBRARIES} ${TSS2_TCTILDR_LIBRARIES})
    target_compile_definitions(test_crypto PRIVATE LH_HAVE_TPM2=1)
else()
    target_compile_definitions(test_crypto PRIVATE LH_NO_TPM2=1)
endif()
add_test(NAME test_crypto COMMAND test_crypto)

# ── Test: test_challenge ──────────────────────────────────────────────────────
add_executable(test_challenge
    test_challenge.c
    ../src/crypto/challenge.c
)
target_include_directories(test_challenge PRIVATE
    ../src/common
    ../src/crypto
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(test_challenge PRIVATE OpenSSL::SSL OpenSSL::Crypto)
add_test(NAME test_challenge COMMAND test_challenge)

# ── Test: test_storage ────────────────────────────────────────────────────────
add_executable(test_storage
    test_storage.c
    ../src/storage/storage.c
)
target_include_directories(test_storage PRIVATE
    ../src/common
    ../src/storage
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(test_storage PRIVATE OpenSSL::Crypto)
add_test(NAME test_storage COMMAND test_storage)
