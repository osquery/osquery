require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libudev < AbstractOsqueryFormula
  desc "API for enumerating and introspecting local devices"
  homepage "https://www.freedesktop.org/software/systemd/man/libudev.html"
  license "LGPL-2.1+"
  url "http://pkgs.fedoraproject.org/repo/pkgs/udev/udev-173.tar.bz2/91a88a359b60bbd074b024883cc0dbde/udev-173.tar.bz2"
  sha256 "70a18315a12f8fc1131f7da5b4dae3606988b69d5c08f96f443b84b8486caaaf"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "2e687971566da425522c4144068dc93d167522ab2973ab77e2b2e76fd292c3a4" => :x86_64_linux
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
