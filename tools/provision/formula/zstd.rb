require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Zstd < AbstractOsqueryFormula
  desc "Zstandard is a real-time compression algorithm"
  homepage "http://zstd.net/"
  license "GPL-2.0+"
  url "https://github.com/facebook/zstd/archive/v1.2.0.tar.gz"
  sha256 "4a7e4593a3638276ca7f2a09dc4f38e674d8317bbea51626393ca73fc047cbfb"
  revision 104

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "c791cd29dd159b1a6fb3770c9a12fbc92e9b16c9a23ed5c67500c93cb727d5ee" => :sierra
    sha256 "d02e6fd44e66a99f7a5c92c1a15c82095aaba4e943e274ccb82e8958a3d4f962" => :x86_64_linux
  end

  depends_on "cmake" => :build

  def install
    ENV.append_to_cflags(" -fPIC -mno-avx")

    system "make", "lib-release"
    system "make", "install", "PREFIX=#{prefix}/"
  end
end
