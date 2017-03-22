require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Rocksdb < AbstractOsqueryFormula
  desc "Persistent key-value store for fast storage environments"
  homepage "http://rocksdb.org"
  url "https://github.com/facebook/rocksdb/archive/v5.1.4.tar.gz"
  sha256 "3ee7e791d12d5359d0cf61c8c22713811dfda024afdd724cdf66ca022992be35"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "c13d7088f586dafbf0210cb9b00a9c5d5f60c96a42467085ee4b82c7860db3cb" => :sierra
    sha256 "911b6a076217fc183e14e4544d34378ae009513d0f40025010e1c69f652505b8" => :x86_64_linux
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
