require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libudev < AbstractOsqueryFormula
  desc "API for enumerating and introspecting local devices"
  homepage "https://www.freedesktop.org/software/systemd/man/libudev.html"
  url "http://pkgs.fedoraproject.org/repo/pkgs/udev/udev-173.tar.bz2/91a88a359b60bbd074b024883cc0dbde/udev-173.tar.bz2"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "8dfa9128e8ba69d3aae0c17340a9e71d041d6272d9eeee929e57b2b5f86e23d2" => :x86_64_linux
  end

  def install
    args = [
      "--disable-introspection",
      "--disable-gudev",
      "--disable-keymap",
      "--disable-mtd-probe",
      "--disable-hwdb",
      "--enable-static",
      "--disable-shared",
    ]

    system "./configure", "--prefix=#{prefix}", *args
    system "make"
    system "make", "install"
  end
end
