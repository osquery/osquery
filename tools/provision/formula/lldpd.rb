require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Lldpd < AbstractOsqueryFormula
  desc "lldpd is an implmentation of LLDP(802.1ab)"
  homepage "https://vincentbernat.github.io/lldpd"
  license "ISC"
  url "https://media.luffy.cx/files/lldpd/lldpd-0.9.6.tar.gz"
  sha256 "e74e2dd7e2a233ca1ff385c925ddae2a916d302819d1433741407d2f8fb0ddd8"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "6f5877f6de12d94d1ac0064cec8656bae93deed429d0d8d7d30475809c397b08" => :sierra
    sha256 "20339d207fd97dcb2f83a96806555354ed7524664b766bdff1656e8d8750d249" => :x86_64_linux
  end

  option :universal

  depends_on "pkg-config" => :build
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
