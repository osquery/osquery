require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Rocksdb < AbstractOsqueryFormula
  desc "Persistent key-value store for fast storage environments"
  homepage "http://rocksdb.org"
  url "https://github.com/facebook/rocksdb/archive/v5.1.4.tar.gz"
  sha256 "3ee7e791d12d5359d0cf61c8c22713811dfda024afdd724cdf66ca022992be35"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "b74a787604a36c77cccad50d1482d21ab1515f80f28f9652d68b4fd052d898af" => :sierra
    sha256 "a826f403087dacd9d58f0e1fc4f456bbae148ed5b7b381a6caf0a82f15123e2b" => :x86_64_linux
  end

  needs :cxx11
  depends_on "snappy"
  depends_on "lz4"

  fails_with :gcc

  def install
    ENV.cxx11

    ENV["PORTABLE"] = "1"
    ENV["LIBNAME"] = "librocksdb_lite"
    ENV.append_to_cflags "-DROCKSDB_LITE=1"

    system "make", "clean"
    system "make", "static_lib"
    system "make", "install", "INSTALL_PATH=#{prefix}"
  end
end
