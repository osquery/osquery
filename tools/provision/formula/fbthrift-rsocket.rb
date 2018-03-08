require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class FbthriftRsocket < AbstractOsqueryFormula
  desc "C++ implementation of RSocket"
  homepage "https://github.com/rsocket"
  license "BSD-3"
  url "https://github.com/rsocket/rsocket-cpp.git",
    :branch => "master"
  revision 200

  depends_on "cmake" => :build
  depends_on "fbthrift-folly"

  def install
    ENV.cxx11

    args = osquery_cmake_args
    args << "-DBUILD_SHARED_LIBS=OFF"

    mkdir "buildroot" do
      system "cmake", "../yarpl", "-DBUILD_TESTS=OFF", *args
      system "make"
      system "make", "install"
    end
  end
end
