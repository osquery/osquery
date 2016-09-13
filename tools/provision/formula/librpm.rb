require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Librpm < AbstractOsqueryFormula
  desc "The RPM Package Manager (RPM) development libraries"
  homepage "http://rpm.org/"
  sha256 "8d65bc5df3056392d7fdfbe00e8f84eb0e828582aa96ef4d6b6afac35a07e8b3"
  url "https://github.com/rpm-software-management/rpm/archive/rpm-4.13.0-rc1.tar.gz"
  version "4.13.0-rc1"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "58c1fcaf9b237561ae03212c7d4047f6d2d39c7262bf823fa26002238fb08c11" => :x86_64_linux
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

    system "./autogen.sh", "--noconfigure"
    system "./configure", "--prefix=#{prefix}", *args
    system "make"
    system "make", "install"
  end
end
