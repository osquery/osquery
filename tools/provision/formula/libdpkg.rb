require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libdpkg < AbstractOsqueryFormula
  desc "Debian package management system"
  homepage "https://wiki.debian.org/Teams/Dpkg"
  url "http://ftp.debian.org/debian/pool/main/d/dpkg/dpkg_1.18.9.tar.xz"
  sha256 "86ac4af917e9e75eb9b6c947a0a11439d1de32f72237413f7ddab17f77082093"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "56e258f8211451485174089a8490496babcfc0ca5dd64ff4c9005d5af623e66a" => :x86_64_linux
  end

  def install
    args = [
      "--disable-dependency-tracking",
      "--disable-silent-rules",
      "--disable-dselect",
      "--disable-start-stop-daemon"
    ]

    system "./configure", "--prefix=#{prefix}", *args
    cd "lib" do
      system "make"
      system "make", "install"
    end
  end
end
