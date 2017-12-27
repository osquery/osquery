require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class GoogleBenchmark < AbstractOsqueryFormula
  desc "C++ microbenchmark support library"
  homepage "https://github.com/google/benchmark"
  license "Apache-2.0"
  url "https://github.com/google/benchmark/archive/v1.3.0.tar.gz"
  sha256 "f19559475a592cbd5ac48b61f6b9cedf87f0b6775d1443de54cfe8f53940b28d"
  head "https://github.com/google/benchmark.git"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "33d981ca1428be694a0e9487c4e81291b6354c584de37d9543c80f19d4339a1b" => :sierra
    sha256 "e60b61331ed05de0ca27e59dbd6eb41acd5f0a1bf955f69ebcdffe1a645e360e" => :x86_64_linux
  end

  depends_on "cmake" => :build

  needs :cxx11

  def install
    ENV.cxx11
    ENV.append_to_cflags "-Wno-zero-length-array"

    system "cmake", *osquery_cmake_args
    system "make"
    system "make", "install"
  end
end
