require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Zstd < Formula
  desc "Zstandard is a real-time compression algorithm"
  homepage "http://zstd.net/"
  url "https://github.com/facebook/zstd/archive/v1.2.0.tar.gz"
  sha256 "4a7e4593a3638276ca7f2a09dc4f38e674d8317bbea51626393ca73fc047cbfb"
  revision 103

  depends_on "cmake" => :build

  def install
    ENV.append_to_cflags(" -fPIC -mno-avx")

    system "make", "lib-release"
    system "make", "install", "PREFIX=#{prefix}/"
  end
end
