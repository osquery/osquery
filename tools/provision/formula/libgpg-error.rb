require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class LibgpgError < AbstractOsqueryFormula
  desc "Common error values for all GnuPG components"
  homepage "https://www.gnupg.org/related_software/libgpg-error/"
  url "https://gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.24.tar.bz2"
  mirror "https://www.mirrorservice.org/sites/ftp.gnupg.org/gcrypt/libgpg-error/libgpg-error-1.24.tar.bz2"
  sha256 "9268e1cc487de5e6e4460fca612a06e4f383072ac43ae90603e5e46783d3e540"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "1c397f85d9117da00482daccb758136c2e672fd8f2b6ac24aa68595766a799dd" => :x86_64_linux
  end

  option :universal

  def install
    ENV.universal_binary if build.universal?

    system "./configure", "--disable-dependency-tracking",
                          "--disable-silent-rules",
                          "--prefix=#{prefix}",
                          "--disable-shared",
                          "--enable-static"
    system "make", "install"
  end

  test do
    system "#{bin}/gpg-error-config", "--libs"
  end
end
