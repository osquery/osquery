require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Rocksdb < AbstractOsqueryFormula
  desc "Persistent key-value store for fast storage environments"
  homepage "http://rocksdb.org"
  url "https://github.com/facebook/rocksdb/archive/v4.11.2.tar.gz"
  sha256 "9374be06fdfccbbdbc60de90b72b5db7040e1bc4e12532e4c67aaec8181b45be"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "036ca6d31d132a1c71a703e83df4b6b0148585405a2a6bdbf2efa2cbaec778a4" => :sierra
    sha256 "a9111aa79915afe327106bfd824185e5f85230b46c2972b8b2d8500131ab8c6c" => :el_capitan
    sha256 "1ca1a32b3709b6c4a0890a929d0a3aa327ddc364ecc1d2dc076a85114272c9db" => :x86_64_linux
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
