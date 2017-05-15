require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Lldpd < AbstractOsqueryFormula
  desc "lldpd is an implmentation of LLDP(802.1ab)"
  homepage "https://vincentbernat.github.io/lldpd"
  url "https://media.luffy.cx/files/lldpd/lldpd-0.9.6.tar.gz"
  sha256 "e74e2dd7e2a233ca1ff385c925ddae2a916d302819d1433741407d2f8fb0ddd8"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "f77c7e03dc2c1a658e2b1dcaa824b9da766c577be9d249996a734d98ec38be37" => :sierra
    sha256 "51bb3a436d7dc9cebaf93067e524c4282ac49dc90e9da9f66b610ff8fd40d899" => :x86_64_linux
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
