require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class GoogleBenchmark < AbstractOsqueryFormula
  desc "C++ microbenchmark support library"
  homepage "https://github.com/google/benchmark"
  url "https://github.com/google/benchmark/archive/v1.0.0.tar.gz"
  sha256 "d2206c263fc1a7803d4b10e164e0c225f6bcf0d5e5f20b87929f137dee247b54"
  head "https://github.com/google/benchmark.git"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "b69e21940600808f50327171dd226fe8649c42ebadfaa222951c759c1366e23b" => :sierra
    sha256 "980e2adab86440ba9c3edea31cf082b1b5f7cd3a08df1f2491c4ebc1d2b7f5c9" => :el_capitan
    sha256 "11e90b22673d2ba5417557a73ed8eaf9b0688f698d16645b907a84d9ee0f0e52" => :x86_64_linux
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
