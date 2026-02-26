#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "galay-ssl::galay-ssl" for configuration "Release"
set_property(TARGET galay-ssl::galay-ssl APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(galay-ssl::galay-ssl PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libgalay-ssl.1.0.0.dylib"
  IMPORTED_SONAME_RELEASE "@rpath/libgalay-ssl.1.dylib"
  )

list(APPEND _cmake_import_check_targets galay-ssl::galay-ssl )
list(APPEND _cmake_import_check_files_for_galay-ssl::galay-ssl "${_IMPORT_PREFIX}/lib/libgalay-ssl.1.0.0.dylib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
