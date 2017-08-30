require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Caf < AbstractOsqueryFormula
  desc "Implementation of the Actor Model for C++"
  homepage "https://actor-framework.org/"
  url "https://github.com/actor-framework/actor-framework.git",
      :branch => "develop"
      #:revision => "9c3822a6e09bb08675f103375a6a643170a36754"
  #url "https://github.com/actor-framework/actor-framework/archive/0.14.6.tar.gz"
  #sha256 "cbc2033896fe41e42604de2f74673971718a40684996650157484485755f7720"
  head "https://github.com/actor-framework/actor-framework.git"
  version "0.14.6"

  needs :cxx11

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
  end

  depends_on "openssl"
  depends_on "cmake" => :build

  # Use both provided and default CXX flags
  patch :DATA

  def install
    args = %W[--prefix=#{prefix} --no-examples --no-qt-examples --no-protobuf-examples --no-curl-examples --no-unit-tests --no-opencl --no-benchmarks --no-python --build-static-only]

    system "./configure", *args
    system "make"
    system "make", "install"
  end

end

__END__
diff --git a/CMakeLists.txt b/CMakeLists.txt
index b56c979..7aaf516 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -305,9 +305,9 @@ if(CAF_IOS_DEPLOYMENT_TARGET)
   endif()
 endif()
 # check if the user provided CXXFLAGS, set defaults otherwise
-if(NOT CMAKE_CXX_FLAGS)
-  set(CMAKE_CXX_FLAGS                   "-std=c++11 -Wextra -Wall -pedantic ${EXTRA_FLAGS}")
-endif()
+#if(NOT CMAKE_CXX_FLAGS)
+set(CMAKE_CXX_FLAGS                   "${CMAKE_CXX_FLAGS} -std=c++11 -Wextra -Wall -pedantic ${EXTRA_FLAGS}")
+#endif()
 if(NOT CMAKE_CXX_FLAGS_DEBUG)
   set(CMAKE_CXX_FLAGS_DEBUG             "-O0 -g")
 endif()
