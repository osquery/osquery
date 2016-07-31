require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Perl < AbstractOsqueryFormula
  desc "Highly capable, feature-rich programming language"
  homepage "https://www.perl.org/"
  url "http://www.cpan.org/src/5.0/perl-5.22.1.tar.xz"
  mirror "https://mirrors.ocf.berkeley.edu/debian/pool/main/p/perl/perl_5.22.1.orig.tar.xz"
  sha256 "9e87317d693ce828095204be0d09af8d60b8785533fadea1a82b6f0e071e5c79"
  revision 1

  head "https://perl5.git.perl.org/perl.git", :branch => "blead"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    prefix "/usr/local/osquery"
    cellar "/usr/local/osquery/Cellar"
    sha256 "a980312494c7919f99ae5a4f3758e17be54e1ef3aa328b2fffff0da250667f2c" => :x86_64_linux
  end

  option "with-dtrace", "Build with DTrace probes"
  option "without-test", "Skip running the build test suite"

  deprecated_option "with-tests" => "with-test"

  depends_on "gdbm" => "with-libgdbm-compat" unless OS.mac?

  def install
    args = %W[
      -des
      -Dprefix=#{prefix}
      -Dman1dir=#{man1}
      -Dman3dir=#{man3}
      -Duseshrplib
      -Duselargefiles
      -Dusethreads
    ]

    args << "-Dusedtrace" if build.with? "dtrace"
    args << "-Dusedevel" if build.head?

    system "./Configure", *args
    system "make"

    # OS X El Capitan's SIP feature prevents DYLD_LIBRARY_PATH from being
    # passed to child processes, which causes the make test step to fail.
    # https://rt.perl.org/Ticket/Display.html?id=126706
    # https://github.com/Homebrew/homebrew/issues/41716
    if MacOS.version < :el_capitan
      system "make", "test" if build.with? "test"
    end

    system "make", "install"
  end

  def caveats; <<-EOS.undent
    By default Perl installs modules in your HOME dir. If this is an issue run:
      `#{opt_bin}/cpan o conf init`
    EOS
  end

  test do
    (testpath/"test.pl").write "print 'Perl is not an acronym, but JAPH is a Perl acronym!';"
    system "#{bin}/perl", "test.pl"
  end
end
