require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Librpm < AbstractOsqueryFormula
  desc "The RPM Package Manager (RPM) development libraries"
  homepage "http://rpm.org/"
  url "https://github.com/rpm-software-management/rpm/releases/download/rpm-4.13.0-release/rpm-4.13.0.tar.bz2"
  sha256 "221166b61584721a8ca979d7d8576078a5dadaf09a44208f69cc1b353240ba1b"
  version "4.13.0"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "37824eb9fb907943a05421425675f74ca87436bfef18167eb28185be82c9a508" => :x86_64_linux
  end

  depends_on "berkeley-db"
  depends_on "beecrypt"
  depends_on "popt"

  def install
    ENV.append "CFLAGS", "-I#{HOMEBREW_PREFIX}/include/beecrypt"

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
      "--with-beecrypt",
    ]

    system "./configure", "--prefix=#{prefix}", *args
    system "make"
    system "make", "install"
  end
end
