require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Lldpd < AbstractOsqueryFormula
  desc "lldpd is an implmentation of LLDP(802.1ab)"
  homepage "https://vincentbernat.github.io/lldpd"
  license "ISC"
  url "https://media.luffy.cx/files/lldpd/lldpd-0.9.6.tar.gz"
  sha256 "e74e2dd7e2a233ca1ff385c925ddae2a916d302819d1433741407d2f8fb0ddd8"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "84feefa7c6b9ebfcdee61b21c4a6263934cd07dc0fed45100e1a26376ddba1b2" => :sierra
    sha256 "6c849a4ec8a701b3dd1db05591ca3fda2032efd105d24bbf3f55747f9ccccc7f" => :x86_64_linux
  end

  depends_on "libevent"

  def install
    args = [
      "--prefix=#{prefix}",
      "--sysconfdir=#{etc}",
      "--localstatedir=/var",
      "--enable-shared=no",
      "--with-privsep-chroot=/var/empty",
      "--with-privsep-user=nobody",
      "--with-privsep-group=nogroup",
    ]

    ENV.append "LDFLAGS", "-lz -liconv" if OS.mac?
    ENV.append "LDFLAGS", "-lz -lm" if OS.linux?

    args << "--with-launchddaemonsdir=no" if OS.mac?

    system "./configure", *args
    system "make"
    system "make", "install"
  end
end
