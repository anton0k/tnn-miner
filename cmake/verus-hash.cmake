if (ARM_TARGET)
  message(STATUS "Wave27 probe: keeping VerusHash enabled on ARM for build investigation")
endif()
if (WITH_VERUSHASH)
    add_definitions(-DTNN_VERUSHASH)

    message(STATUS "Building with VerusHash support")

    file(GLOB_RECURSE verusHeaders
      src/crypto/verus/*.h
    )

    file(GLOB_RECURSE verusSources
      src/crypto/verus/*.cpp
      src/crypto/verus/*.c
      src/net/verus/*.cpp
      src/coins/mine_verus.cpp
    )

    # wave41: use the already accepted ccminer-monkins Verus scanner/hash
    # objects on ARM. The standalone Wave41 runner produced accepted live
    # shares with these exact objects; the local TNN provider path only reached
    # low-difficulty submits. The TNN integration still owns Stratum/session
    # logic and mine_verus.cpp, while scanhash_verus/Haraka/CLHash come from the
    # ccminer build products.
    if (ARM_TARGET)
      set(WAVE41_CCMINER_VERUS_OBJECT_DIR "$ENV{HOME}/odroid-mining-lab/miners/ccminer-monkins/verus"
          CACHE PATH "Directory containing ccminer Verus object files for Wave41 TNN integration")
      set(WAVE41_CCMINER_VERUS_OBJECTS
        "${WAVE41_CCMINER_VERUS_OBJECT_DIR}/ccminer-verusscan.o"
        "${WAVE41_CCMINER_VERUS_OBJECT_DIR}/ccminer-haraka.o"
        "${WAVE41_CCMINER_VERUS_OBJECT_DIR}/ccminer-haraka_portable.o"
        "${WAVE41_CCMINER_VERUS_OBJECT_DIR}/ccminer-verus_clhash_portable.o"
      )
      foreach(obj ${WAVE41_CCMINER_VERUS_OBJECTS})
        if (NOT EXISTS "${obj}")
          message(FATAL_ERROR "Wave41 ccminer Verus object missing: ${obj}")
        endif()
      endforeach()
      list(FILTER verusSources EXCLUDE REGEX ".*/src/crypto/verus/verusscan\\.cpp$")
      list(FILTER verusSources EXCLUDE REGEX ".*/src/crypto/verus/haraka\\.c$")
      list(FILTER verusSources EXCLUDE REGEX ".*/src/crypto/verus/haraka_portable\\.c$")
      list(FILTER verusSources EXCLUDE REGEX ".*/src/crypto/verus/verus_clhash\\.cpp$")
      list(FILTER verusSources EXCLUDE REGEX ".*/src/crypto/verus/verus_clhash_portable\\.cpp$")
      list(APPEND verusSources ${WAVE41_CCMINER_VERUS_OBJECTS})
      message(STATUS "Wave41: linking ccminer Verus objects from ${WAVE41_CCMINER_VERUS_OBJECT_DIR}")
    endif()

    if (ARM_TARGET)
      set_source_files_properties(src/crypto/verus/haraka.c COMPILE_FLAGS "-march=armv8-a+crypto -flax-vector-conversions")
      set_source_files_properties(src/crypto/verus/verus_clhash.cpp COMPILE_FLAGS "-march=armv8-a+crypto -flax-vector-conversions")
    else()
      set_source_files_properties(src/crypto/verus/haraka.c COMPILE_FLAGS -maes)
      set_source_files_properties(src/crypto/verus/verus_clhash.cpp COMPILE_FLAGS "-maes -mpclmul")
    endif()
    

    # list(APPEND xelisSources
    #   src/coins/mine_xelis.cpp
    # )

    list(APPEND HEADERS_CRYPTO
      ${verusHeaders}
    )

    list(APPEND SOURCES_CRYPTO
      ${verusSources}
    )
else()
    remove_definitions(/DTNN_VERUSHASH)
endif()
