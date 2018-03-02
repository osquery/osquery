require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class GoogleBenchmark < AbstractOsqueryFormula
  desc "C++ microbenchmark support library"
  homepage "https://github.com/google/benchmark"
  license "Apache-2.0"
  url "https://github.com/google/benchmark/archive/v1.0.0.tar.gz"
  sha256 "d2206c263fc1a7803d4b10e164e0c225f6bcf0d5e5f20b87929f137dee247b54"
  head "https://github.com/google/benchmark.git"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "9fadf0f008384d1b8f1c9c947d49de14716ca615af67e189edaa5f87f61e03a7" => :sierra
    sha256 "288a64a4433c85fd71893eb8ca1a5f2b4ade8fce6a67c6cee21a850405197603" => :x86_64_linux
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
