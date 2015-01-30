get_source_path("gtest" gtest_source_path)
get_build_path("gtest" gtest_build_path)

ExternalProject_Add(
  gtest
  URL https://googletest.googlecode.com/files/gtest-1.7.0.zip
  URL_HASH SHA1=f85f6d2481e2c6c4a18539e391aa4ea8ab0394af
  INSTALL_COMMAND ${third_party_mkdir} && cp -R ${gtest_source_path}/include/gtest ${third_party_include} && cp ${gtest_build_path}/libgtest.a ${third_party_lib}
)
