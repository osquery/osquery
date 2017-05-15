require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libdpkg < AbstractOsqueryFormula
  desc "Debian package management system"
  homepage "https://wiki.debian.org/Teams/Dpkg"
  url "http://ftp.debian.org/debian/pool/main/d/dpkg/dpkg_1.18.23.tar.xz"
  sha256 "cc08802a0cea2ccd0c10716bc71531ff9b9234dd454b83a59f71117a37f36923"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "837fbbf8d84d29c95c103b134daf50b55854dd69aec79ca7adebee9351b716b6" => :x86_64_linux
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
