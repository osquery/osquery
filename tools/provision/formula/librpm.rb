require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Librpm < AbstractOsqueryFormula
  desc "The RPM Package Manager (RPM) development libraries"
  homepage "http://rpm.org/"
  url "http://rpm.org/releases/testing/rpm-4.13.0-rc1.tar.bz2"
  version "4.13.0-rc1"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    prefix "/usr/local/osquery"
    cellar "/usr/local/osquery/Cellar"
    sha256 "038a8f25463cfd002d734dd2ddcfbc564373f35237fcc499f98638d9f3f75345" => :x86_64_linux
  end

  def install
    ENV.append_to_cflags "-I#{Formula["nss"].include}"
    ENV.append_to_cflags "-I#{Formula["nspr"].include}"

    args = [
      "--disable-plugins",
      "--disable-nls",
      "--disable-dependency-tracking",
      "--disable-silent-rules",
      "--without-nss",
      "--without-archive",
      "--disable-python",
      "--disable-ndb",
      "--disable-nss",
      "--disable-shared",
      "--without-beecrypt",
      "--without-external-db",
      "--without-lua",
      "--without-cap",
      "--without-selinux",
      "--without-libintl-prefix",
      "--without-libiconv-prefix",
      ""
    ]

    system "./configure", "--prefix=#{prefix}", *args
    system "make"
    system "make", "install"
  end
end
