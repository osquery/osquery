require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libgcrypt < AbstractOsqueryFormula
  desc "Cryptographic library based on the code from GnuPG"
  homepage "https://directory.fsf.org/wiki/Libgcrypt"
  url "https://gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.6.5.tar.bz2"
  mirror "https://www.mirrorservice.org/sites/ftp.gnupg.org/gcrypt/libgcrypt/libgcrypt-1.6.5.tar.bz2"
  sha256 "f49ebc5842d455ae7019def33eb5a014a0f07a2a8353dc3aa50a76fd1dafa924"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "d33dac41ffc0fadad593ecafdd6bbd275826b3abfbefadfedfd76b5db1853d24" => :x86_64_linux
  end

  depends_on "libgpg-error"

  resource "config.h.ed" do
    url "https://raw.githubusercontent.com/Homebrew/patches/ec8d133/libgcrypt/config.h.ed"
    version "113198"
    sha256 "d02340651b18090f3df9eed47a4d84bed703103131378e1e493c26d7d0c7aab1"
  end

  option :universal

  def install
    ENV.universal_binary if build.universal?

    args = [
      "--disable-dependency-tracking",
      "--disable-silent-rules",
      "--disable-avx-support",
      "--disable-avx2-support",
      "--disable-drng-support",
      "--disable-pclmul-support",
      "--disable-shared",
      "--enable-static",
      "--prefix=#{prefix}",
      "--disable-asm",
      "--with-libgpg-error-prefix=#{Formula["libgpg-error"].opt_prefix}",
      "--with-gpg-error-prefix=#{Formula["libgpg-error"].opt_prefix}",
    ]

    system "./configure", *args
    if build.universal?
      buildpath.install resource("config.h.ed")
      system "ed -s - config.h <config.h.ed"
    end

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
