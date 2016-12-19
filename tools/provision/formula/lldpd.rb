require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Lldpd < AbstractOsqueryFormula
  desc "lldpd is an implmentation of LLDP(802.1ab)"
  homepage "https://vincentbernat.github.io/lldpd"
  url "https://media.luffy.cx/files/lldpd/lldpd-0.9.5.tar.gz"
  sha256 "e9585c52f14808f03f6b6c3a9163c95b542a47b18abe002992b155d143a1a247"

  option :universal

  depends_on "pkg-config" => :build
  depends_on "readline"
  depends_on "libevent"
  depends_on "net-snmp" if build.with? "snmp"
  depends_on "jansson" if build.with? "json"

  def install
    if OS.mac?
      readline = Formula["readline"]
      args = [
        "--prefix=#{prefix}",
        "--sysconfdir=#{etc}",
        "--localstatedir=#{var}",
        "--with-xml",
        "--with-readline",
        "--with-privsep-chroot=/var/empty",
        "--with-privsep-user=nobody",
        "--with-privsep-group=nogroup",
        "--with-launchddaemonsdir=no",
        "CPPFLAGS=-I#{readline.include} -DRONLY=1",
        "LDFLAGS=-L#{readline.lib}",
      ]
      args << (build.with?("snmp") ? "--with-snmp" : "--without-snmp")
      args << (build.with?("json") ? "--with-json" : "--without-json")
    else
      args = [
        "--prefix=#{prefix}",
        "--sysconfdir=#{etc}",
        "--localstatedir=#{var}",
      ]
    end

    system "./configure", *args
    system "make"
    system "make", "install"
  end
end
