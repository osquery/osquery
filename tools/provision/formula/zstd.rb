require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Zstd < Formula
  desc "Zstandard is a real-time compression algorithm"
  homepage "http://zstd.net/"
  license "GPL-2.0+"
  url "https://github.com/facebook/zstd/archive/v1.2.0.tar.gz"
  sha256 "4a7e4593a3638276ca7f2a09dc4f38e674d8317bbea51626393ca73fc047cbfb"
  revision 103

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "1c284eb035ee3db8e00362214e21433d8af6d3ff5c576a67b8d3f140f773d14f" => :sierra
    sha256 "732b5f9cad9755681842227d0be3fed8486b79db40d3869d4052204a64709f57" => :x86_64_linux
  end

  depends_on "cmake" => :build

  def install
    ENV.append_to_cflags(" -fPIC -mno-avx")

    system "make", "lib-release"
    system "make", "install", "PREFIX=#{prefix}/"
  end
end
