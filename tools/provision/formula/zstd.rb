require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Zstd < Formula
  desc "Zstandard is a real-time compression algorithm"
  homepage "http://zstd.net/"
  url "https://github.com/facebook/zstd/archive/v1.2.0.tar.gz"
  sha256 "4a7e4593a3638276ca7f2a09dc4f38e674d8317bbea51626393ca73fc047cbfb"
  revision 101

  #bottle do
  #  cellar :any
  #  sha256 "bc2ff6cb7373b79d53896ded9b54fbaf225dc24621dee26dbe9d482ff592274a" => :sierra
  #  sha256 "70cd43a12ae9a638221725bb3ca770d8080ed437c3f9f34a8789e44642e40e65" => :el_capitan
  #  sha256 "2d0e998725164b7cee9197f5cf5d254370250528adfb1b0328b65683fd2a1ce5" => :yosemite
  #end
  #option "without-pzstd", "Build without parallel (de-)compression tool"

  depends_on "cmake" => :build

  def install
    ENV.append_to_cflags(" -fPIC")

    system "make", "lib"
    system "make", "install", "PREFIX=#{prefix}/"
  end
end