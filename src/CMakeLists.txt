set(SOURCE_FILES
    # OCH and related
    aead/och/trans.c
    aead/och/em256.c
    aead/och/sponge512.c
    aead/och/od512.c
    aead/och/och256.c
    aead/och/ocsimple.c
    # AES256-GCM
    aead/nae/aes256-gcm/aes256gcm.c
    # BoringSSL
    aead/evp_aead/evp_aead.c
    # Blake2b-OPP-MEM
    aead/nae/blake2b-opp-mem/opp.c
    # Blake2b
    hash/blake2b/sse/blake2b.c
    # SHA256
    hash/sha256/sha256.c
    # SHA3
    hash/sha3/sha3.c
    # Poly1305
    axu/poly1305/poly1305.c
    # Polyval
    hash/polyval/mul64_nohw.c
    hash/polyval/gf128mul_nohw.c
    hash/polyval/polyval.c
    # Ascon
    hash/ascon/ascon.c
    # AES128-OCB3
    aead/nae/aes-ocb3/ocb.c
    # Aegis
    aead/nae/libaegis/aegis.c)

if(CR_x86_64)

  set(SOURCE_FILES
      ${SOURCE_FILES}
      # Ciphers
      cipher/aes256/aes256ecb.c
      cipher/rijndael256/rijndael256ecb.c)

  set(ASM_SOURCE_FILES
      # polyval
      hash/polyval/backend/polyval-clmulni_asm.S
      # SHA256
      hash/sha256/x86_64/sha256-x86_64-linux.S
      # AES256-GCM
      aead/nae/aes256-gcm/aes256gcm_skylake.s)

elseif(CR_aarch64)

  set(ASM_SOURCE_FILES # TODO?
  )

else()

  message(
    FATAL_ERROR
      "unsupported architecture ${CMAKE_SYSTEM_PROCESSOR}, only x86_64 and aarch64/arm64 are supported"
  )

endif()

add_library(cryptography-run ${SOURCE_FILES} ${ASM_SOURCE_FILES})

target_include_directories(cryptography-run PUBLIC ../include)

target_link_libraries(cryptography-run PRIVATE libsodium)
target_link_libraries(cryptography-run PRIVATE libXKCP)
target_link_libraries(cryptography-run PRIVATE ascon)
target_link_libraries(cryptography-run PRIVATE boringssl)
target_link_libraries(cryptography-run PRIVATE libaegis)
