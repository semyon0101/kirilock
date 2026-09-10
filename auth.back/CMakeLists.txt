cmake_minimum_required(VERSION 3.23)

project(
  AuthLib
  LANGUAGES C
  DESCRIPTION "Authentication library"
)

# Export compile_commands.json for clangd/LSP
if(PROJECT_IS_TOP_LEVEL)
  set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE
    BOOL "Export compile_commands.json" FORCE)

  file(CREATE_LINK
    "${CMAKE_BINARY_DIR}/compile_commands.json"
    "${CMAKE_CURRENT_SOURCE_DIR}/compile_commands.json"
    COPY_ON_ERROR
    SYMBOLIC
  )
endif()

# Options
option(AUTHLIB_BUILD_EXAMPLES "Build example application" OFF)
option(AUTHLIB_ENABLE_IPO "Enable Interprocedural Optimization (LTO)" ON)

# Dependencies resolution via standard tools
find_package(PkgConfig REQUIRED)

pkg_check_modules(SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
pkg_check_modules(PAM REQUIRED IMPORTED_TARGET pam)


# Main Library Target
add_library(authLib)
add_library(authLib::authLib ALIAS authLib)

target_sources(authLib
  PRIVATE
    src/fingerprint.c
    src/password.c
  PUBLIC
    FILE_SET HEADERS
    BASE_DIRS
      include
    FILES
      include/auth/fingerprint.h
      include/auth/password.h
)

# Standard and Compilation Flags
target_compile_features(authLib PUBLIC c_std_11)

target_compile_options(authLib
  PRIVATE
    $<$<C_COMPILER_ID:GNU,Clang,AppleClang>:
      -Wall
      -Wextra
      -Wpedantic
    >
)

# External Linking
target_link_libraries(authLib
  PRIVATE
    PkgConfig::SYSTEMD
    PkgConfig::PAM
)

# Target-scoped IPO (LTO)
if(AUTHLIB_ENABLE_IPO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT ipo_supported OUTPUT ipo_output)
  if(ipo_supported)
    set_target_properties(authLib PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
  else()
    message(WARNING "IPO is not supported: ${ipo_output}")
  endif()
endif()

# Examples Sub-target
if(AUTHLIB_BUILD_EXAMPLES)
  add_executable(authlib_example)

  target_sources(authlib_example
    PRIVATE
      example/main.c
  )

  target_compile_features(authlib_example PRIVATE c_std_11)

  target_compile_options(authlib_example
    PRIVATE
      $<$<C_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -Wpedantic>
  )

  target_link_libraries(authlib_example
    PRIVATE
      authLib::authLib
  )

  include(GNUInstallDirs)

endif()
