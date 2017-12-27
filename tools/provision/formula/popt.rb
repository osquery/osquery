require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Popt < AbstractOsqueryFormula
  desc "Library like getopt(3) with a number of enhancements"
  homepage "http://rpm5.org"
  license "X11"
  url "http://rpm5.org/files/popt/popt-1.16.tar.gz"
  sha256 "e728ed296fe9f069a0e005003c3d6b2dde3d9cad453422a10d6558616d304cc8"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "9ce9ed60a436613a9b0f5ef5f8626bb7e697258ade9fc269631ae402362a8df2" => :sierra
    sha256 "4a558a63baba5636d839c7cd6946c19a1a92471430709250bf2bccc5caa79c4d" => :x86_64_linux
  end

  def install
    system "./configure", "--disable-debug",
                          "--disable-dependency-tracking",
                          "--prefix=#{prefix}",
                          "--disable-shared",
                          "--enable-static"
    system "make", "install"
  end
end
