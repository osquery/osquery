require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libdpkg < AbstractOsqueryFormula
  desc "Debian package management system"
  homepage "https://wiki.debian.org/Teams/Dpkg"
  license "GPL-2.0+"
  url "https://launchpad.net/debian/+archive/primary/+sourcefiles/dpkg/1.19.0.5/dpkg_1.19.0.5.tar.xz"
  mirror "http://snapshot.debian.org/archive/debian/20180121T094839Z/pool/main/d/dpkg/dpkg_1.19.0.5.tar.xz"
  sha256 "818046927a7f77c1bcbbad7d8dbc04cdf0f3e6ec4e1a4f9d313378ecc69d85b5"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "c4762be902915a3eb31d59da73e392f9458a8f21d9e6484171a4f500f341a765" => :x86_64_linux
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
