require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Librpm < AbstractOsqueryFormula
  desc "The RPM Package Manager (RPM) development libraries"
  homepage "http://rpm.org/"
  url "http://ftp.rpm.org/releases/rpm-4.14.x/rpm-4.14.0.tar.bz2"
  sha256 "06a0ad54600d3c42e42e02701697a8857dc4b639f6476edefffa714d9f496314"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "cdec41658bf34f547819025b88910e2f94ed6929067755cf3cc08f7499391ee8" => :sierra
    sha256 "521cd60e71aa3364af8ca9a997e61432dcca85901ec0bed46f495d34088b8678" => :x86_64_linux
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
