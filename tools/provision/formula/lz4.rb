require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Lz4 < AbstractOsqueryFormula
  desc "Lossless compression algorithm"
  homepage "http://www.lz4.info/"
  url "https://github.com/Cyan4973/lz4/archive/r131.tar.gz"
  version "r131"
  sha256 "9d4d00614d6b9dec3114b33d1224b6262b99ace24434c53487a0c8fd0b18cfed"
  head "https://github.com/Cyan4973/lz4.git"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "f20ebf1414ccf6f12d8e2c9196802be6e42e7426e2520da90618d517df9eb1bf" => :sierra
    sha256 "c76439790f13b3c5b729d888a55826025a5bf54c832e7993d76692b47be7b28c" => :x86_64_linux
  end

  def install
    system "make", "install", "PREFIX=#{prefix}"

    # Remove shared library
    rm_rf lib/"liblz4.so"
  end

  test do
    input = "testing compression and decompression"
    input_file = testpath/"in"
    input_file.write input
    output_file = testpath/"out"
    system "sh", "-c", "cat #{input_file} | #{bin}/lz4 | #{bin}/lz4 -d > #{output_file}"
    assert_equal output_file.read, input
  end
end
