require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Automake < AbstractOsqueryFormula
  desc "Tool for generating GNU Standards-compliant Makefiles"
  homepage "https://www.gnu.org/software/automake/"
  url "https://ftp.gnu.org/gnu/automake/automake-1.15.1.tar.gz"
  sha256 "988e32527abe052307d21c8ca000aa238b914df363a617e38f4fb89f5abf6260"

  depends_on "autoconf"

  def install
    ENV["PERL"] = "/usr/bin/perl"

    system "./configure", "--prefix=#{prefix}"
    system "make", "install"

    # if OS.mac?
    #   # Our aclocal must go first. See:
    #   # https://github.com/Homebrew/homebrew/issues/10618
    #   (share/"aclocal/dirlist").write <<~EOS
    #     #{HOMEBREW_PREFIX}/share/aclocal
    #     /usr/share/aclocal
    #   EOS
    # end
  end

  test do
    (testpath/"test.c").write <<~EOS
      int main() { return 0; }
    EOS
    (testpath/"configure.ac").write <<~EOS
      AC_INIT(test, 1.0)
      AM_INIT_AUTOMAKE
      AC_PROG_CC
      AC_CONFIG_FILES(Makefile)
      AC_OUTPUT
    EOS
    (testpath/"Makefile.am").write <<~EOS
      bin_PROGRAMS = test
      test_SOURCES = test.c
    EOS
    system bin/"aclocal"
    system bin/"automake", "--add-missing", "--foreign"
    system "autoconf"
    system "./configure"
    system "make"
    system "./test"
  end
end
