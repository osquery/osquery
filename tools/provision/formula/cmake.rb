require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Cmake < AbstractOsqueryFormula
  desc "Cross-platform make"
  homepage "https://www.cmake.org/"
  url "https://cmake.org/files/v3.12/cmake-3.12.0-rc1.tar.gz"
  sha256 "aac7476c40018006c36ae4ee4137d355d824f0f16b065871c9f989a96500fc00"
  revision 100

  head "https://cmake.org/cmake.git"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "e7e2ab13b5793cfa86e178989babd97d096976e65d9b05ac862918383f0e94b5" => :sierra
    sha256 "5db395e595d9e37f9ea85f36340dbee5c995a27e8a959e7ce77358b8fa490289" => :x86_64_linux
  end

  # The `with-qt` GUI option was removed due to circular dependencies if
  # CMake is built with Qt support and Qt is built with MySQL support as MySQL uses CMake.
  # For the GUI application please instead use `brew cask install cmake`.

  patch :DATA

  def install
    args = %W[
      --prefix=#{prefix}
      --no-system-libs
      --parallel=#{ENV.make_jobs}
      --datadir=/share/cmake
      --docdir=/share/doc/cmake
      --mandir=/share/man
      --system-bzip2
      --system-liblzma
    ]

    system "./bootstrap", *args
    system "make"
    system "make", "install"

    elisp.install "Auxiliary/cmake-mode.el"
  end
end

__END__
diff --git a/Utilities/cmlibuv/CMakeLists.txt b/Utilities/cmlibuv/CMakeLists.txt
index 4c8e228..9605d6a 100644
--- a/Utilities/cmlibuv/CMakeLists.txt
+++ b/Utilities/cmlibuv/CMakeLists.txt
@@ -175,7 +175,7 @@ if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
 endif()
 
 if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
-  list(APPEND uv_libraries dl rt)
+  list(APPEND uv_libraries dl rt pthread)
   list(APPEND uv_headers
     include/uv-linux.h
     )
