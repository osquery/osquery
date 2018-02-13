require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class FbthriftWangle < AbstractOsqueryFormula
  desc "C++ networking library"
  homepage "https://github.com/rsocket"
  license "BSD-3"
  url "https://github.com/facebook/wangle/archive/v2017.12.25.00.tar.gz"
  sha256 "02abb153bc5be63a82d39fd4af879a09915ea2093412c749c86f878816ad0184"
  revision 200

  depends_on "cmake" => :build

  def install
    ENV.cxx11

    args = osquery_cmake_args
    args << "-DBUILD_SHARED_LIBS=OFF"

    cd "wangle" do
      system "cmake", ".", "-DBUILD_TESTS=OFF", *args
      system "make"
      system "make", "install"
    end
  end
end
