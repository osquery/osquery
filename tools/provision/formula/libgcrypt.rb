require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libgcrypt < AbstractOsqueryFormula
  desc "Cryptographic library based on the code from GnuPG"
  homepage "https://directory.fsf.org/wiki/Libgcrypt"
  license "LGPL-2.1+"
  url "https://gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.8.1.tar.bz2"
  mirror "https://www.mirrorservice.org/sites/ftp.gnupg.org/gcrypt/libgcrypt/libgcrypt-1.8.1.tar.bz2"
  sha256 "7a2875f8b1ae0301732e878c0cca2c9664ff09ef71408f085c50e332656a78b3"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "b8a827a90f1514b518362094f8ab39e557d96690306c9bef131ffe34eeac16b6" => :x86_64_linux
  end

  depends_on "libgpg-error"

  resource "config.h.ed" do
    url "https://raw.githubusercontent.com/Homebrew/patches/ec8d133/libgcrypt/config.h.ed"
    version "113198"
    sha256 "d02340651b18090f3df9eed47a4d84bed703103131378e1e493c26d7d0c7aab1"
  end

  def install
    args = [
      "--disable-avx-support",
      "--disable-avx2-support",
      "--disable-drng-support",
      "--disable-pclmul-support",
      "--disable-sse41-support",
      "--disable-optimization",
      "--disable-asm",
      "--with-libgpg-error-prefix=#{Formula["osquery/osquery-local/libgpg-error"].opt_prefix}",
      "--with-gpg-error-prefix=#{Formula["osquery/osquery-local/libgpg-error"].opt_prefix}",
    ]

    system "./configure", *osquery_autoconf_flags, *args
    buildpath.install resource("config.h.ed")
    system "ed -s - config.h <config.h.ed"

    cd "cipher" do
      system "make"
    end

    cd "random" do
      system "make"
    end

    cd "mpi" do
      system "make"
    end

    cd "compat" do
      system "make"
    end

    cd "src" do
      system "make"
      system "make", "install"
    end
  end
end
