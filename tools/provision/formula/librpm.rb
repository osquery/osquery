require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Librpm < AbstractOsqueryFormula
  desc "The RPM Package Manager (RPM) development libraries"
  homepage "http://rpm.org/"
  license "LGPL-3.0+"
  url "http://ftp.rpm.org/releases/rpm-4.14.x/rpm-4.14.0.tar.bz2"
  sha256 "06a0ad54600d3c42e42e02701697a8857dc4b639f6476edefffa714d9f496314"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "035096a03a14fd8059ffbe4d2174e1d09eccbe3c46696a7990859539105771d5" => :sierra
    sha256 "f81690e32704f0107a33693709aadc5197faa9919b10c735e28e5e1aa94ce75b" => :x86_64_linux
  end

  depends_on "berkeley-db"
  depends_on "beecrypt"
  depends_on "popt"

  def install
    ENV.append "CFLAGS", "-I#{HOMEBREW_PREFIX}/include/beecrypt"
    ENV.append "LDFLAGS", "-lz -liconv" if OS.mac?

    args = [
      "--disable-dependency-tracking",
      "--disable-silent-rules",
      "--with-external-db",
      "--without-selinux",
      "--without-lua",
      "--without-cap",
      "--without-archive",
      "--disable-nls",
      "--disable-rpath",
      "--disable-plugins",
      "--disable-shared",
      "--disable-python",
      "--enable-static",
      "--enable-zstd=no",
      "--with-crypto=beecrypt",
    ]

    inreplace "Makefile.in", "rpm2cpio.$(OBJEXT)", "rpm2cpio.$(OBJEXT) lib/poptALL.$(OBJEXT) lib/poptQV.$(OBJEXT)" if OS.mac?
    inreplace "Makefile.in", "rpmspec-rpmspec.$(OBJEXT)", "rpmspec-rpmspec.$(OBJEXT) lib/poptQV.$(OBJEXT)" if OS.mac?

    system "./configure", "--prefix=#{prefix}", *args
    system "make"
    system "make", "install"
  end
end
