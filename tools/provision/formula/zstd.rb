require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Zstd < AbstractOsqueryFormula
  desc "Zstandard is a real-time compression algorithm"
  homepage "http://zstd.net/"
  license "GPL-2.0+"
  url "https://github.com/facebook/zstd/archive/v1.2.0.tar.gz"
  sha256 "4a7e4593a3638276ca7f2a09dc4f38e674d8317bbea51626393ca73fc047cbfb"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "dbd2b877c0a5a4d6e76ebcc5a2b72b510573ed8027f4c5b9aeccd4297b366eb4" => :sierra
    sha256 "e30994deb83d33093fc4aab3a8cdf0c99c91b6da1e0281317a616d19f5bafdda" => :x86_64_linux
  end

  depends_on "cmake" => :build

  def install
    ENV.append_to_cflags(" -fPIC -mno-avx")

    system "make", "lib-release"
    system "make", "install", "PREFIX=#{prefix}/"
  end
end
