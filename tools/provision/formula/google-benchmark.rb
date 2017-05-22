require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class GoogleBenchmark < AbstractOsqueryFormula
  desc "C++ microbenchmark support library"
  homepage "https://github.com/google/benchmark"
  url "https://github.com/google/benchmark/archive/v1.0.0.tar.gz"
  sha256 "d2206c263fc1a7803d4b10e164e0c225f6bcf0d5e5f20b87929f137dee247b54"
  head "https://github.com/google/benchmark.git"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "e1b22a234863cc2ff50ca25c95d7a2120a6ae0248a205729d750b541972911c7" => :sierra
    sha256 "79e9ed34b99971f8288be3a5a3521cf51840fc63690d6d583e2d607a30ceaf45" => :x86_64_linux
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
