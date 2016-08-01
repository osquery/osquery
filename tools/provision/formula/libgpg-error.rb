require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class LibgpgError < AbstractOsqueryFormula
  desc "Common error values for all GnuPG components"
  homepage "https://www.gnupg.org/related_software/libgpg-error/"
  url "https://gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.22.tar.bz2"
  mirror "https://www.mirrorservice.org/sites/ftp.gnupg.org/gcrypt/libgpg-error/libgpg-error-1.22.tar.bz2"
  sha256 "f2a04ee6317bdb41a625bea23fdc7f0b5a63fb677f02447c647ed61fb9e69d7b"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "1ae09fed0eb3a6ac2ad2d083f166a2dfa527987a78ee158587674286c9dee70a" => :x86_64_linux
  end

  option :universal

  def install
    ENV.universal_binary if build.universal?

    system "./configure", "--disable-dependency-tracking",
                          "--disable-silent-rules",
                          "--prefix=#{prefix}",
                          "--enable-static"
    system "make", "install"
  end

  test do
    system "#{bin}/gpg-error-config", "--libs"
  end
end
