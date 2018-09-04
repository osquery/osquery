require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Zlib < AbstractOsqueryFormula
  desc "General-purpose lossless data-compression library"
  homepage "https://zlib.net/"
  url "https://zlib.net/zlib-1.2.11.tar.gz"
  mirror "https://downloads.sourceforge.net/project/libpng/zlib/1.2.11/zlib-1.2.11.tar.gz"
  sha256 "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any
    sha256 "30548658b43cf66979f2756680fbb32d3c19c967e478ceea22d07f536b22bbce" => :high_sierra
    sha256 "6f604280b9e056da163b81cef3076b2e39bbd2b8d3cc8c36d27c19c472c760a4" => :x86_64_linux 
  end

  keg_only :provided_by_macos

  # https://zlib.net/zlib_how.html
  resource "test_artifact" do
    url "https://zlib.net/zpipe.c"
    version "20051211"
    sha256 "68140a82582ede938159630bca0fb13a93b4bf1cb2e85b08943c26242cf8f3a6"
  end

  def install
    system "./configure", "--prefix=#{prefix}"
    system "make", "install"
  end

  test do
    testpath.install resource("test_artifact")
    system ENV.cc, "zpipe.c", "-I#{include}", "-L#{lib}", "-lz", "-o", "zpipe"

    touch "foo.txt"
    output = "./zpipe < foo.txt > foo.txt.z"
    system output
    assert_predicate testpath/"foo.txt.z", :exist?
  end
end
