require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Fbthrift < AbstractOsqueryFormula
  desc "Thrift is a serialization and RPC framework for service communication."
  homepage "https://github.com/rsocket"
  license "BSD-3"
  url "https://github.com/facebook/fbthrift/archive/v2017.12.25.00.tar.gz"
  sha256 "432b5c15272160fb481737dbc3203c01b7383fce67a04d81d951952212e93ad5"
  revision 200

  depends_on "cmake" => :build

  def install
    ENV.cxx11

    args = osquery_cmake_args
    args << "-DBUILD_SHARED_LIBS=OFF"
    args << "-DDOUBLE_CONVERSION_LIBRARY=#{default_prefix}/lib"
    args << "-DDOUBLE_CONVERSION_INCLUDE_DIR=#{default_prefix}/include/double-conversion"

    cd "build" do
      system "cmake", "..", *args
      system "make"
      system "make", "install"
    end
  end
end
