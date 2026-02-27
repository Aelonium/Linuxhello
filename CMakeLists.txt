cmake_minimum_required(VERSION 3.16)
project(LinuxHello VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── Compiler flags ────────────────────────────────────────────────────────────
add_compile_options(
    -Wall -Wextra -Wpedantic
    -Wformat=2 -Wformat-security
    -Wstrict-prototypes -Wmissing-prototypes
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fPIE
)
add_link_options(-pie -Wl,-z,relro,-z,now)

# ── Find dependencies ─────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)

# OpenSSL (required: ECC key generation, ECDSA signing/verification, PBKDF2)
find_package(OpenSSL REQUIRED)

# tpm2-tss ESAPI (optional: TPM 2.0 support)
pkg_check_modules(TSS2_ESYS  tss2-esys)
pkg_check_modules(TSS2_RC    tss2-rc)

# GLib/GIO (optional: fprintd D-Bus client)
pkg_check_modules(GLIB  glib-2.0)
pkg_check_modules(GIO   gio-2.0)

# libpam (required: PAM module)
find_library(PAM_LIBRARY pam)
find_path(PAM_INCLUDE_DIR security/pam_modules.h
    PATHS /usr/include /usr/local/include)

# ── Feature detection ─────────────────────────────────────────────────────────
if(TSS2_ESYS_FOUND AND TSS2_RC_FOUND)
    set(HAVE_TPM2 TRUE)
    message(STATUS "TPM 2.0 (tpm2-tss ESAPI): enabled")
else()
    set(HAVE_TPM2 FALSE)
    message(STATUS "TPM 2.0 (tpm2-tss ESAPI): NOT found – degraded mode only")
endif()

if(GLIB_FOUND AND GIO_FOUND)
    set(HAVE_GLIB TRUE)
    message(STATUS "GLib/GIO (fprintd D-Bus): enabled")
else()
    set(HAVE_GLIB FALSE)
    message(STATUS "GLib/GIO (fprintd D-Bus): NOT found – biometric disabled")
endif()

if(PAM_LIBRARY AND PAM_INCLUDE_DIR)
    set(HAVE_PAM TRUE)
    message(STATUS "libpam: enabled")
else()
    set(HAVE_PAM FALSE)
    message(STATUS "libpam: NOT found – PAM module will not be built")
endif()

# ── Source groups ─────────────────────────────────────────────────────────────

# Common (header-only, no library target needed)

# Crypto library
set(CRYPTO_SOURCES
    src/crypto/challenge.c
    src/crypto/tpm_ops.c
)
add_library(lh_crypto STATIC ${CRYPTO_SOURCES})
target_include_directories(lh_crypto PUBLIC
    src/common
    src/crypto
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(lh_crypto PUBLIC OpenSSL::SSL OpenSSL::Crypto)

if(HAVE_TPM2)
    target_compile_definitions(lh_crypto PUBLIC LH_HAVE_TPM2=1)
    target_include_directories(lh_crypto PUBLIC ${TSS2_ESYS_INCLUDE_DIRS})
    target_link_libraries(lh_crypto PUBLIC
        ${TSS2_ESYS_LIBRARIES}
        ${TSS2_RC_LIBRARIES}
    )
    target_compile_options(lh_crypto PUBLIC ${TSS2_ESYS_CFLAGS_OTHER})
else()
    # No tpm2-tss: use inline stubs compiled into tpm_ops.c via LH_NO_TPM2
    target_compile_definitions(lh_crypto PUBLIC LH_NO_TPM2=1)
endif()

# Storage library
set(STORAGE_SOURCES
    src/storage/storage.c
)
add_library(lh_storage STATIC ${STORAGE_SOURCES})
target_include_directories(lh_storage PUBLIC
    src/common
    src/storage
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(lh_storage PUBLIC OpenSSL::Crypto)

# Biometric library (requires GLib)
if(HAVE_GLIB)
    set(BIO_SOURCES
        src/biometric/fprintd_client.c
    )
    add_library(lh_bio STATIC ${BIO_SOURCES})
    target_include_directories(lh_bio PUBLIC
        src/common
        src/biometric
        ${GLIB_INCLUDE_DIRS}
        ${GIO_INCLUDE_DIRS}
    )
    target_link_libraries(lh_bio PUBLIC
        ${GLIB_LIBRARIES}
        ${GIO_LIBRARIES}
    )
    target_compile_options(lh_bio PUBLIC
        ${GLIB_CFLAGS_OTHER}
        ${GIO_CFLAGS_OTHER}
    )
else()
    # Provide a stub library so daemon and enroll tool can still link
    add_library(lh_bio STATIC src/biometric/fprintd_stub.c)
    target_compile_definitions(lh_bio PUBLIC LH_NO_BIOMETRIC=1)
    target_include_directories(lh_bio PUBLIC src/common src/biometric)
endif()

# ── Auth daemon (lhd) ─────────────────────────────────────────────────────────
add_executable(lhd
    src/daemon/lhd.c
)
target_include_directories(lhd PRIVATE src/common src/daemon)
target_link_libraries(lhd PRIVATE lh_crypto lh_storage lh_bio)

# ── Enrollment CLI (lh-enroll) ────────────────────────────────────────────────
add_executable(lh-enroll
    src/enroll/lh-enroll.c
)
target_include_directories(lh-enroll PRIVATE src/common src/enroll)
target_link_libraries(lh-enroll PRIVATE lh_crypto lh_storage lh_bio)

# ── PAM module ────────────────────────────────────────────────────────────────
if(HAVE_PAM)
    add_library(pam_linuxhello SHARED
        src/pam/pam_linuxhello.c
    )
    set_target_properties(pam_linuxhello PROPERTIES
        PREFIX ""            # output: pam_linuxhello.so (no "lib" prefix)
        SUFFIX ".so"
    )
    target_include_directories(pam_linuxhello PRIVATE
        src/common
        src/pam
        ${PAM_INCLUDE_DIR}
    )
    target_link_libraries(pam_linuxhello PRIVATE ${PAM_LIBRARY})

    # Install to PAM security modules directory
    if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
        set(PAM_MODULE_DIR "/lib/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu/security"
            CACHE PATH "PAM security modules directory")
    endif()
    install(TARGETS pam_linuxhello DESTINATION ${PAM_MODULE_DIR})
else()
    message(STATUS "PAM module will not be built (libpam not found)")
endif()

# ── Install targets ───────────────────────────────────────────────────────────
include(GNUInstallDirs)

install(TARGETS lhd       RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
install(TARGETS lh-enroll RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(FILES systemd/linuxhello.service
    DESTINATION /lib/systemd/system)

install(FILES pam.d/linuxhello
    DESTINATION /etc/pam.d)

# ── Tests ─────────────────────────────────────────────────────────────────────
enable_testing()
add_subdirectory(tests)
