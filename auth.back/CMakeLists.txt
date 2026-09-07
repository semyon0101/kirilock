cmake_minimum_required(VERSION 3.23)

project(AuthLib)

option(AUTHLIB_COMPILE_EXAMPLE "Compile an examle" OFF)
option(AUTHLIB_ENABLE_IPO "Check for and use IPO support" ON)
option(AUTHLIB_NDEBUG "Debug" ON)

add_library(authLib)

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
target_compile_options(authLib
    PRIVATE -Wall -Wextra)

if(AUTHLIB_NDEBUG)
  target_compile_definitions(authLib PRIVATE NDEBUG)
endif()

if(AUTHLIB_ENABLE_IPO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT result OUTPUT output)
  if(result)
    message("IPO is supported, enabling IPO")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
  else()
    message(WARNING "IPO is not supported: ${output}")
  endif()
endif()


if(AUTHLIB_COMPILE_EXAMPLE)
  add_executable(test)
  target_compile_features(test PRIVATE c_std_11)
  target_compile_options(test
    PRIVATE -Wall -Wextra)

  target_sources(test
    PRIVATE
      example/main.c
  )

  target_link_libraries(test
    PRIVATE
      authLib
  )
  if(AUTHLIB_NDEBUG)
    target_compile_definitions(test PRIVATE NDEBUG)
  endif()

endif()

