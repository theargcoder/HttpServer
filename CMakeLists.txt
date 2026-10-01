cmake_minimum_required(VERSION 4.4)

project(HttpServer LANGUAGES C CXX)

# ============================================================
# C / C++ / CMake
# ============================================================

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ============================================================
# Build type
# ============================================================

set(BIN2CHARS_BUILD_TYPES Debug Release RelWithDebInfo Generic)

if(NOT CMAKE_CONFIGURATION_TYPES)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS ${BIN2CHARS_BUILD_TYPES})

  if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE
        Release
        CACHE STRING "Build type" FORCE)
  endif()
else()
  # Multi-config generators: Visual Studio, Xcode, Ninja Multi-Config.
  list(APPEND CMAKE_CONFIGURATION_TYPES Generic)
  list(REMOVE_DUPLICATES CMAKE_CONFIGURATION_TYPES)

  set(CMAKE_CONFIGURATION_TYPES
      "${CMAKE_CONFIGURATION_TYPES}"
      CACHE STRING "Available build configurations" FORCE)
endif()

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" SYSTEM_ARCH)

# ============================================================
# Boost
# ============================================================

find_package(Boost REQUIRED COMPONENTS unit_test_framework)

get_target_property(BIN2CHARS_BOOST_HEADERS Boost::headers
                    INTERFACE_INCLUDE_DIRECTORIES)
message(STATUS "Boost_INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}")
message(STATUS "Boost::headers includes: ${BIN2CHARS_BOOST_HEADERS}")

# ============================================================
# Compiler detection
# ============================================================

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  set(IS_GCC TRUE)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(IS_CLANG TRUE)
endif()

# ============================================================
# Explode in CI builds on failure
# ============================================================

option(BIN2CHARS_CIBUILD "Enable CI-specific test behavior" OFF)

# ============================================================
# Compiler flag support detection
#
# Every warning is tested against the actual compiler before it is added to the
# project's warning list.
# ============================================================

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

function(filter_supported_flags INPUT_LIST OUTPUT_LIST LANGUAGE)

  message(
    "-- Checking supported compile time flags ... this may take ~30 seconds")
  set(SUPPORTED_FLAGS "")
  set(CMAKE_REQUIRED_QUIET TRUE)

  foreach(FLAG IN LISTS ${INPUT_LIST})

    string(MD5 FLAG_HASH "${FLAG}")
    set(CHECK_VAR "HAS_${LANGUAGE}_FLAG_${FLAG_HASH}")

    if(LANGUAGE STREQUAL "C")
      check_c_compiler_flag("${FLAG}" ${CHECK_VAR})
    elseif(LANGUAGE STREQUAL "CXX")
      check_cxx_compiler_flag("${FLAG}" ${CHECK_VAR})
    else()
      message(
        FATAL_ERROR
          "filter_supported_flags(): unsupported language '${LANGUAGE}'")
    endif()

    if(${CHECK_VAR})
      list(APPEND SUPPORTED_FLAGS "${FLAG}")
    else()
      message(STATUS "Skipping unsupported ${LANGUAGE} compiler flag: ${FLAG}")
    endif()

  endforeach()

  set(${OUTPUT_LIST}
      "${SUPPORTED_FLAGS}"
      PARENT_SCOPE)

endfunction()

# ============================================================
# C warnings
# ============================================================

set(C_WARNINGS
    # Fundamental
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    # Control flow / logic
    -Wduplicated-cond
    -Wduplicated-branches
    -Wmisleading-indentation
    -Wparentheses
    -Wempty-body
    -Wswitch
    -Wswitch-enum
    # Initialization / lifetime
    -Wuninitialized
    -Wmaybe-uninitialized
    -Winit-self
    -Wreturn-type
    -Wuse-after-free
    # Arrays / bounds
    -Warray-bounds=2
    -Warray-parameter=2
    -Wzero-length-bounds
    -Wsizeof-array-div
    -Wsizeof-pointer-div
    -Wsizeof-pointer-memaccess
    # Pointer / memory correctness
    -Wnull-dereference
    -Wpointer-arith
    -Wcast-align=strict
    -Wcast-qual
    -Wrestrict
    # Integer conversions
    -Wconversion
    -Wsign-conversion
    -Wsign-compare
    -Wchar-subscripts
    # Integer UB
    -Wshift-overflow=2
    -Wshift-negative-value
    -Wdiv-by-zero
    # Floating-point
    -Wfloat-conversion
    -Wfloat-equal
    # String / formatting
    -Wformat=2
    -Wformat-overflow=2
    -Wformat-truncation=2
    -Wformat-security
    -Wstringop-overflow
    -Wstringop-overread
    -Wstringop-truncation
    # Allocation
    -Walloc-zero
    -Walloca
    # Language / declarations
    -Wredundant-decls
    -Wmissing-declarations
    # Undefined / suspicious constructs
    -Wundef
    -Wtrigraphs
    -Wcomment
    -Wmultistatement-macros
    -Wvla
    # Unused
    -Wunused
    -Wunused-parameter
    -Wunused-variable
    -Wno-unused-function
    -Wunused-label
    -Wunused-value
    -Wunused-but-set-variable
    -Wunused-but-set-parameter)

# ============================================================
# C++ warnings
# ============================================================

set(CXX_WARNINGS
    ${C_WARNINGS}
    # C++ conversions / arithmetic
    -Warith-conversion
    -Wdouble-promotion
    # Aliasing
    -Wstrict-aliasing=3
    # C++ object model
    -Wnon-virtual-dtor
    -Wdelete-non-virtual-dtor
    -Woverloaded-virtual
    -Wold-style-cast
    -Wreorder
    -Wmismatched-tags
    -Wplacement-new=2
    -Wsized-deallocation
    -Wrange-loop-construct
    -Wpessimizing-move
    -Wredundant-move
    -Wself-move
    # Initialization / aggregate issues
    -Wmissing-field-initializers
    -Wmissing-braces
    # C++ declarations / attributes
    -Wmissing-attributes
    -Wmissing-noreturn)

# ============================================================
# GCC-specific warnings
# ============================================================

if(IS_GCC)

  set(GCC_ONLY_WARNINGS
      -Walloc-size -Wstring-compare -Wtype-limits -Wtrampolines -Wframe-address
      -Wvector-operation-performance)

  list(APPEND C_WARNINGS ${GCC_ONLY_WARNINGS})
  list(APPEND CXX_WARNINGS ${GCC_ONLY_WARNINGS})

endif()

# ============================================================
# Filter unsupported warnings
#
# At this point every warning has been defined. Each language is checked
# independently.
# ============================================================

filter_supported_flags(C_WARNINGS C_WARNINGS_SUPPORTED C)

filter_supported_flags(CXX_WARNINGS CXX_WARNINGS_SUPPORTED CXX)

set(C_WARNINGS "${C_WARNINGS_SUPPORTED}")
set(CXX_WARNINGS "${CXX_WARNINGS_SUPPORTED}")

# ============================================================
# Architecture - best for performance
# ============================================================

set(NATIVE_ARCH_FLAGS)

if(SYSTEM_ARCH MATCHES "^(x86_64|amd64|i386|i686)$")

  if(IS_GCC OR IS_CLANG)
    list(APPEND NATIVE_ARCH_FLAGS -march=native)
  endif()

elseif(SYSTEM_ARCH MATCHES "^(arm64|aarch64)$")

  if(IS_GCC OR IS_CLANG)
    list(APPEND NATIVE_ARCH_FLAGS -mcpu=native)
  endif()

endif()

# ============================================================
# Generic architecture - for ABIs and stuff
# ============================================================

set(GENERIC_ARCH_FLAGS)

if(SYSTEM_ARCH MATCHES "^(x86_64|amd64|x64)$")

  if(IS_GCC OR IS_CLANG)
    list(APPEND GENERIC_ARCH_FLAGS -march=x86-64 -mtune=generic)
  endif()

elseif(SYSTEM_ARCH MATCHES "^(arm64|aarch64)$")

  if(IS_GCC OR IS_CLANG)
    list(APPEND GENERIC_ARCH_FLAGS -march=armv8-a)
  endif()

endif()

# ============================================================
# External libraries
# ============================================================

# add_subdirectory(abc External lib)

# ============================================================
# Library
# ============================================================

add_library(HttpServer STATIC src/HttpServer.cpp src/TcpSocket.cpp)

set_target_properties(HttpServer PROPERTIES LINKER_LANGUAGE CXX)

target_compile_features(HttpServer PUBLIC cxx_std_23)

target_include_directories(HttpServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(HttpServer PRIVATE Boost::headers)

# ============================================================
# GCC / Clang
# ============================================================

if(IS_GCC OR IS_CLANG)

  # ==========================================================
  # Debug
  # ==========================================================

  if(CMAKE_BUILD_TYPE STREQUAL "Debug")

    # Common Debug flags supported by GCC and Clang.
    add_compile_options(
      ${NATIVE_ARCH_FLAGS}
      -O0
      -g3
      -fno-omit-frame-pointer
      -fno-optimize-sibling-calls
      -fno-sanitize-recover=all
      "$<$<COMPILE_LANGUAGE:C>:${C_WARNINGS}>"
      "$<$<COMPILE_LANGUAGE:CXX>:${CXX_WARNINGS}>")

    # Compiler-specific Debug flags.
    if(IS_GCC)

      add_compile_options(
        -fno-ipa-sra
        -fno-inline
        -fno-inline-functions
        -fno-inline-small-functions
        -fno-default-inline
        -fsanitize=address
        -fsanitize=undefined
        -fsanitize=leak
        -fsanitize=bounds-strict
        -fsanitize=alignment
        -fsanitize=object-size
        -fsanitize=pointer-overflow
        -fsanitize=float-cast-overflow
        -fsanitize=float-divide-by-zero
        -fsanitize=bool
        -fsanitize=enum
        -fsanitize=vptr
        -fsanitize=builtin
        -ftrivial-auto-var-init=pattern
        -fstack-protector-strong
        -fstack-clash-protection)

      add_link_options(-fsanitize=address -fsanitize=undefined -fsanitize=leak
                       -fno-sanitize-recover=all)

    elseif(IS_CLANG)

      add_compile_options(
        -fsanitize=address
        -fsanitize=undefined
        -fsanitize=alignment
        -fsanitize=pointer-overflow
        -fsanitize=float-cast-overflow
        -fsanitize=float-divide-by-zero
        -fsanitize=vptr
        -ftrivial-auto-var-init=pattern
        -fstack-protector-strong)

      add_link_options(-fsanitize=address -fsanitize=undefined
                       -fno-sanitize-recover=all)

      add_compile_options(-Wno-invalid-feature-combination)

    endif()

    # ==========================================================
    # Release
    # ==========================================================

  elseif(CMAKE_BUILD_TYPE STREQUAL "Release")

    add_compile_options(
      -O3 -DNDEBUG -fno-omit-frame-pointer ${NATIVE_ARCH_FLAGS}
      "$<$<COMPILE_LANGUAGE:C>:${C_WARNINGS}>"
      "$<$<COMPILE_LANGUAGE:CXX>:${CXX_WARNINGS}>")

    if(IS_CLANG)
      add_compile_options(-Wno-invalid-feature-combination)
    endif()

    if(IS_GCC)

      add_compile_options(-funroll-loops -fprefetch-loop-arrays)

    endif()

    # ==========================================================
    # RelWithDebInfo
    #
    # Optimized but still pleasant in CodeLLDB.
    # ==========================================================

  elseif(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")

    add_compile_options(
      -O3
      -g3
      -DNDEBUG
      -fno-omit-frame-pointer
      ${NATIVE_ARCH_FLAGS}
      "$<$<COMPILE_LANGUAGE:C>:${C_WARNINGS}>"
      "$<$<COMPILE_LANGUAGE:CXX>:${CXX_WARNINGS}>")

    if(IS_CLANG)
      add_compile_options(-Wno-invalid-feature-combination)
    endif()

    # ==========================================================
    # Generic
    #
    # Aggressively optimized, architecture-baseline distribution.
    # ==========================================================

  elseif(CMAKE_BUILD_TYPE STREQUAL "Generic")

    add_compile_options(
      -O0 -g3 ${GENERIC_ARCH_FLAGS} "$<$<COMPILE_LANGUAGE:C>:${C_WARNINGS}>"
      "$<$<COMPILE_LANGUAGE:CXX>:${CXX_WARNINGS}>")

  endif()
endif()

# ============================================================
# Static linking of GCC runtimes
#
# Never do this for the Debug sanitizer build.
# ============================================================

if((IS_GCC OR IS_CLANG)
   AND NOT APPLE
   AND NOT CMAKE_BUILD_TYPE STREQUAL "Debug")

  add_link_options(-static-libgcc -static-libstdc++)

endif()

# ============================================================
# Tests
#
# This is YOUR source tree. Everything configured above applies here.
# ============================================================

enable_testing()

# ============================================================
# BPF stuff
# ============================================================

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)

find_program(BPF_CLANG clang REQUIRED)
find_program(CMAKE_OBJCOPY objcopy REQUIRED)

set(BPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/xdp_redirect.bpf.o)

set(BPF_EMBEDDED_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/xdp_redirect_embedded.o)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
  set(BPF_TARGET_ARCH x86)

  set(OBJCOPY_TARGET elf64-x86-64)
  set(OBJCOPY_ARCH i386:x86-64)

elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
  set(BPF_TARGET_ARCH arm64)

  set(OBJCOPY_TARGET elf64-littleaarch64)
  set(OBJCOPY_ARCH aarch64)

else()
  message(
    FATAL_ERROR "Unsupported BPF target architecture: ${CMAKE_SYSTEM_PROCESSOR}"
  )
endif()

# ------------------------------------------------------------
# Compile BPF ELF
# ------------------------------------------------------------

add_custom_command(
  OUTPUT ${BPF_OBJECT}
  COMMAND ${BPF_CLANG} -target bpf -D__TARGET_ARCH_${BPF_TARGET_ARCH} -O2 -g -c
          ${CMAKE_CURRENT_SOURCE_DIR}/bpf/xdp_redirect.bpf.c -o ${BPF_OBJECT}
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bpf/xdp_redirect.bpf.c
  VERBATIM)

# ------------------------------------------------------------
# Embed BPF ELF into a normal host object file
# ------------------------------------------------------------

add_custom_command(
  OUTPUT ${BPF_EMBEDDED_OBJECT}
  COMMAND ${CMAKE_OBJCOPY} -I binary -O ${OBJCOPY_TARGET} -B ${OBJCOPY_ARCH}
          xdp_redirect.bpf.o xdp_redirect_embedded.o
  DEPENDS ${BPF_OBJECT}
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  VERBATIM)

add_custom_target(xdp_redirect_bpf ALL DEPENDS ${BPF_EMBEDDED_OBJECT})

add_dependencies(HttpServer xdp_redirect_bpf)

# The embedded ELF becomes part of libHttpServer.a
target_sources(HttpServer PRIVATE ${BPF_EMBEDDED_OBJECT})

target_link_libraries(HttpServer PUBLIC PkgConfig::LIBBPF)

add_subdirectory(test)
