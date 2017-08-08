require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Rocksdb < AbstractOsqueryFormula
  desc "Persistent key-value store for fast storage environments"
  homepage "http://rocksdb.org"
  url "https://github.com/facebook/rocksdb/archive/v5.1.4.tar.gz"
  sha256 "3ee7e791d12d5359d0cf61c8c22713811dfda024afdd724cdf66ca022992be35"
  revision 103

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "18a52b1e96c93b9a99cc33ad9a2eb0b6db0ecd864f25f24684bb6117a44f00f2" => :sierra
    sha256 "5754ea9999e374273ab7d766e5bc0dae5ee43e544f3d93b4402cc57112dffbf6" => :x86_64_linux
  end

  needs :cxx11
  depends_on "zstd"

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
