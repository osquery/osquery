require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Openipmi < AbstractOsqueryFormula
  desc "OpenIPMI is an effort to create a full-function IPMI system to allow full access to all IPMI information on a server and to abstract it to a level that will make it easy to use"
  homepage "http://openipmi.sourceforge.net/"
  url "https://sourceforge.net/projects/openipmi/files/OpenIPMI%202.0%20Library/OpenIPMI-2.0.23.tar.gz"
  sha256 "035c5cc0566dd161c3a6528e5a5e8982c960a0fe3619564831397c46552f8b68"
  revision 101

  depends_on "pkg-config" => :build
  depends_on "ncurses"
  depends_on "popt"

  def install
    args = [
      "--prefix=#{prefix}",
      "--enable-shared=no",
    ]

    system "./configure", *args
    system "make"
    system "make", "install", "-i"
  end
end
