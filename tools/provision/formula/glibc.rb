require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Glibc < AbstractOsqueryFormula
  desc "The GNU C Library"
  homepage "https://www.gnu.org/software/libc"
  url "ftp.gnu.org/gnu/glibc/glibc-2.19.tar.bz2"
  sha256 "2e293f714187044633264cd9ce0183c70c3aa960a2f77812a6390a3822694d15"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "46c47d3e6df6dbbc7d1574e3c2f660d3aa81d47efd742512e6673fe2ca94308d" => :x86_64_linux
  end

  # binutils 2.20 or later is required
  depends_on "binutils" => [:build, :recommended]

  # Linux kernel headers 2.6.19 or later are required
  depends_on "linux-headers" => [:build, :recommended]

  keg_only "osquery runtime"

  def install
    ENV["CFLAGS"] = "-U_FORTIFY_SOURCE -fno-stack-protector -O2"

    mkdir "build" do
      args = [
        "--disable-debug",
        "--disable-dependency-tracking",
        "--disable-silent-rules",
        "--prefix=#{prefix}",
        "--enable-obsolete-rpc",
        "--without-selinux",
        "--disable-sanity-checks",
      ] # Fix error: selinux/selinux.h: No such file or directory
      args << "--with-binutils=#{Formula["binutils"].bin}" if build.with? "binutils" or true
      args << "--with-headers=#{Formula["linux-headers"].include}" if build.with? "linux-headers" or true
      system "../configure", *args

      system "make" # Fix No rule to make target libdl.so.2 needed by sprof
      system "make", "install"
      prefix.install_symlink "lib" => "lib64"
    end
  end

  def post_install
    # Fix permissions
    chmod 0755, [lib/"ld-#{version}.so", lib/"libc-#{version}.so"]

    # Compile locale definition files
    mkdir_p lib/"locale"
    locales = ENV.map { |k, v| v if k[/^LANG$|^LC_/] && v != "C" }.compact
    locales << "en_US.UTF-8" # Required by gawk make check
    locales.uniq.each do |locale|
      lang, charmap = locale.split(".", 2)
      if !charmap.nil?
        system bin/"localedef", "-i", lang, "-f", charmap, locale
      else
        system bin/"localedef", "-i", lang, locale
      end
    end

    # Set the local time zone
    sys_localtime = Pathname.new "/etc/localtime"
    brew_localtime = Pathname.new prefix/"etc/localtime"
    (prefix/"etc").install_symlink sys_localtime if sys_localtime.exist? && !brew_localtime.exist?

    # Install ld.so symlink.
    ln_sf lib/"ld-linux-x86-64.so.2", HOMEBREW_PREFIX/"lib/ld.so"
  end

  test do
    system "#{lib}/ld-#{version}.so 2>&1 |grep Usage"
    system "#{lib}/libc-#{version}.so", "--version"
    system "#{bin}/locale", "--version"
  end
end
