ExternalProject_Add(
  libboost
  URL http://downloads.sourceforge.net/project/boost/boost/1.57.0/boost_1_57_0.tar.gz
  URL_HASH SHA1=55366a96bb76440ab140047065650f1d73dbfd8c
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND ./bootstrap.sh  --prefix=${third_party_prefix} --with-toolset=clang
  BUILD_COMMAND ./b2 cxxflags=-I${third_party_include} cxxflags=-I${third_party_include}/python2.7 linkflags=-L${third_party_lib}
  INSTALL_COMMAND ./b2 install
  DEPENDS libpython libbzip2 libzlib
)
