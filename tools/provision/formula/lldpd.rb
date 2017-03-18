require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Lldpd < AbstractOsqueryFormula
  desc "lldpd is an implmentation of LLDP(802.1ab)"
  homepage "https://vincentbernat.github.io/lldpd"
  url "https://media.luffy.cx/files/lldpd/lldpd-0.9.6.tar.gz"
  sha256 "e74e2dd7e2a233ca1ff385c925ddae2a916d302819d1433741407d2f8fb0ddd8"

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

    args << "--with-launchddaemonsdir=no" if OS.mac?

    system "./configure", *args
    system "make"
    system "make", "install"
  end
end
