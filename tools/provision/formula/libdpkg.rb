require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libdpkg < AbstractOsqueryFormula
  desc "Debian package management system"
  homepage "https://wiki.debian.org/Teams/Dpkg"
  license "GPL-2.0+"
  url "http://download.openpkg.org/components/cache/dpkg/dpkg_1.18.23.tar.xz"
  sha256 "cc08802a0cea2ccd0c10716bc71531ff9b9234dd454b83a59f71117a37f36923"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "cd38c7f2af0fa21326777204c432ada3dc8275b583041de0bfb57193052fcf53" => :x86_64_linux
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
