require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Rapidjson < AbstractOsqueryFormula
  desc "JSON parser/generator for C++ with SAX and DOM style APIs"
  homepage "https://miloyip.github.io/rapidjson/"
  license "MIT and JSON"
  url "https://github.com/miloyip/rapidjson/archive/v1.1.0.tar.gz"
  sha256 "bf7ced29704a1e696fbccf2a2b4ea068e7774fa37f6d7dd4039d0787f8bed98e"
  head "https://github.com/miloyip/rapidjson.git"
  revision 201

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "173d111815b6d7b3e2edd3fde4f498bebca2d62643778735a8323e6ca6a2692d" => :sierra
    sha256 "0b867773af2bbcb897dac9642a7505e6a13cbe598e645009e84462639254e09e" => :x86_64_linux
  end

  depends_on "cmake" => :build

  patch :DATA

  def install
    # Needed with LLVM 5.0.1
    append "CXXFLAGS", "-Wno-zero-as-null-pointer-constant -Wno-shadow"

    args = std_cmake_args
    args << "-DRAPIDJSON_BUILD_DOC=OFF"
    system "cmake", ".", *args
    system "make", "install"
  end
end

__END__
diff --git a/CMakeLists.txt b/CMakeLists.txt
index ceda71b..9fc5273 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -50,7 +50,7 @@ if(CCACHE_FOUND)
 endif(CCACHE_FOUND)
 
 if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
-    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -Wall -Wextra -Werror")
+    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror")
     if (RAPIDJSON_BUILD_CXX11)
         if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS "4.7.0")
             set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
@@ -73,7 +73,7 @@ if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
         endif()
     endif()
 elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
-    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -Wall -Wextra -Werror -Wno-missing-field-initializers")
+    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -Wno-missing-field-initializers")
     if (RAPIDJSON_BUILD_CXX11)
         set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
     endif()
