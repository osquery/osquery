require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class LibgpgError < AbstractOsqueryFormula
  desc "Common error values for all GnuPG components"
  homepage "https://www.gnupg.org/related_software/libgpg-error/"
  license "LGPL-2.1+"
  url "https://gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.27.tar.bz2"
  mirror "https://www.mirrorservice.org/sites/ftp.gnupg.org/gcrypt/libgpg-error/libgpg-error-1.27.tar.bz2"
  sha256 "4f93aac6fecb7da2b92871bb9ee33032be6a87b174f54abf8ddf0911a22d29d2"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "660dcd0c4ef16b262d6f4d776533848b72db2ba7bd28d1970dc1d48b4dce96f4" => :x86_64_linux
  end

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
