require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Rocksdb < AbstractOsqueryFormula
  desc "Persistent key-value store for fast storage environments"
  homepage "http://rocksdb.org"
  url "https://github.com/facebook/rocksdb/archive/v4.9.tar.gz"
  sha256 "7c96c7e7facc11c15f57c608a3b256af79283accb5988d7b2f4f810e29c68c0b"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "7648b8f2e4d16a9cad88d83fdf476a475c583d345f89f131a2f36eccdc9ac0a4" => :el_capitan
    sha256 "360eba1e275f4ec2b4d3ec3c26641206c947be3354d4329c185fe9c78569aa25" => :x86_64_linux
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
