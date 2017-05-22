require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Lz4 < AbstractOsqueryFormula
  desc "Lossless compression algorithm"
  homepage "http://www.lz4.info/"
  url "https://github.com/Cyan4973/lz4/archive/r131.tar.gz"
  version "r131"
  sha256 "9d4d00614d6b9dec3114b33d1224b6262b99ace24434c53487a0c8fd0b18cfed"
  head "https://github.com/Cyan4973/lz4.git"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "3d5b83d360ed5fcdcf04b98d6b54b77c3ac3a29b0a8b004789cd59b6301db210" => :sierra
    sha256 "5d109b6dce79439b7736838e6034cafdf2526e8e31f3d3fe23e609dd6b7bcdef" => :x86_64_linux
  end

  def install
    system "make", "install", "PREFIX=#{prefix}"
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
