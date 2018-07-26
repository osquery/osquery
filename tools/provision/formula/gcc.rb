require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Gcc < AbstractOsqueryFormula
  desc "GNU compiler collection"
  homepage "https://gcc.gnu.org"
  license "GPL-3.0+"
  url "https://ftp.gnu.org/gnu/gcc/gcc-5.4.0/gcc-5.4.0.tar.bz2"
  mirror "http://ftpmirror.gnu.org/gcc/gcc-5.4.0/gcc-5.4.0.tar.bz2"
  sha256 "608df76dec2d34de6558249d8af4cbee21eceddbcb580d666f7a5a583ca3303a"
  revision 202

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "28f8788ccd1c595bf535afb3f2fa2083737ea04e96b65f8498c2866fccc531a2" => :x86_64_linux
  end

  depends_on "zlib"

  def version_suffix
    version.to_s.slice(/\d/)
  end

  def osmajor
    `uname -r`.chomp
  end

  resource "mpfr" do
    url "https://mirrors.ocf.berkeley.edu/debian/pool/main/m/mpfr4/mpfr4_3.1.5.orig.tar.xz"
    mirror "https://ftp.gnu.org/gnu/mpfr/mpfr-3.1.5.tar.xz"
    sha256 "015fde82b3979fbe5f83501986d328331ba8ddf008c1ff3da3c238f49ca062bc"
  end

  resource "libmpc" do
    url "https://ftp.gnu.org/gnu/mpc/mpc-1.0.3.tar.gz"
    mirror "http://multiprecision.org/mpc/download/mpc-1.0.3.tar.gz"
    sha256 "617decc6ea09889fb08ede330917a00b16809b8db88c29c31bfbb49cbf88ecc3"
  end

  resource "isl" do
    url "http://isl.gforge.inria.fr/isl-0.15.tar.bz2"
    mirror "ftp://gcc.gnu.org//pub/gcc/infrastructure/isl-0.15.tar.bz2"
    sha256 "8ceebbf4d9a81afa2b4449113cee4b7cb14a687d7a549a963deb5e2a41458b6b"
  end

  resource "gmp" do
    url "https://gmplib.org/download/gmp/gmp-6.1.1.tar.xz"
    mirror "https://ftp.gnu.org/gnu/gmp/gmp-6.1.1.tar.xz"
    sha256 "d36e9c05df488ad630fff17edb50051d6432357f9ce04e34a09b3d818825e831"
  end

  def install
    mkdir "deps/gmp" do
      (buildpath/"deps/gmp").install resource("gmp")
      args = %W[--with-pic --build=core2-linux-gnu]

      system "./configure", *osquery_autoconf_flags, *args
      system "make"
      system "make", "install"
    end

    mkdir "deps/mpfr" do
      (buildpath/"deps/mpfr").install resource("mpfr")
      args = %W[--with-gmp=#{prefix}]

      system "./configure", *osquery_autoconf_flags, *args
      system "make"
      system "make", "install"
    end

    mkdir "deps/libmpc" do
      (buildpath/"deps/libmpc").install resource("libmpc")
      args = %W[--with-gmp=#{prefix} --with-mpfr=#{prefix}]

      system "./configure", *osquery_autoconf_flags, *args
      system "make"
      system "make", "install"
    end

    mkdir "deps/isl" do
      (buildpath/"deps/isl").install resource("isl")
      args = %W[--with-pic --with-gmp-prefix=#{prefix}]

      system "./configure", *osquery_autoconf_flags, *args
      system "make"
      system "make", "install"
    end

    # GCC will suffer build errors if forced to use a particular linker.
    ENV.delete "LD"

    # C, C++ compilers are always built
    languages = %w[c c++]

    args = []

    # Fix for GCC 4.4 and older that do not support -static-libstdc++
    # gengenrtl: error while loading shared libraries: libstdc++.so.6
    mkdir_p lib
    ln_s ["/usr/lib64/libstdc++.so.6", "/lib64/libgcc_s.so.1"], lib
    binutils = Formula["binutils"].prefix/"x86_64-pc-linux-gnu/bin"
    args += [
      "--with-native-system-header-dir=#{legacy_prefix}/include",
      "--with-local-prefix=#{default_prefix}",
      "--with-build-time-tools=#{binutils}",
    ]

    args += [
      "--prefix=#{prefix}",
      "--enable-languages=#{languages.join(",")}",
      # Make most executables versioned to avoid conflicts.
      "--program-suffix=-#{version_suffix}",
      "--with-gmp=#{prefix}",
      "--with-mpfr=#{prefix}",
      "--with-mpc=#{prefix}",
      "--with-isl=#{prefix}",
      "--with-system-zlib",
      "--enable-libstdcxx-time=yes",
      "--enable-stage1-checking",
      "--enable-checking=release",
      "--enable-lto",
      # Use 'bootstrap-debug' build configuration to force stripping of object
      # files prior to comparison during bootstrap (broken by Xcode 6.3).
      #"--with-build-config=bootstrap-debug",
      "--disable-werror",
      "--with-pkgversion=Homebrew #{name} #{pkg_version} #{build.used_options*" "}".strip,
      "--with-bugurl=https://github.com/Homebrew/homebrew/issues",
    ]

    # Fix cc1: error while loading shared libraries: libisl.so.15
    args << "--with-boot-ldflags=-static-libstdc++ -static-libgcc #{ENV["LDFLAGS"]}"

    # "Building GCC with plugin support requires a host that supports
    # -fPIC, -shared, -ldl and -rdynamic."
    args << "--enable-plugin"

    # The pre-Mavericks toolchain requires the older DWARF-2 debugging data
    # format to avoid failure during the stage 3 comparison of object files.
    # See: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=45248
    args << "--with-dwarf2"
    args << "--disable-nls"
    args << "--disable-multilib"

    # Ensure correct install names when linking against libgcc_s;
    # see discussion in https://github.com/Homebrew/homebrew/pull/34303
    inreplace "libgcc/config/t-slibgcc-darwin", "@shlib_slibdir@", "#{default_prefix}/lib/gcc/#{version_suffix}"
    inreplace "libitm/method-serial.cc", "assert (ok);", "(void) ok;"

    # osquery: speed up the build by skipping the bootstrap.
    args << "--disable-bootstrap"
    args << "--disable-libgomp"

    # Do not move this above the arguments configurations.
    ENV["LDFLAGS"] = "-Wl,-rpath,#{default_prefix}/lib"

    mkdir "build" do
      system "../configure", *args
      system "make"
      system "make", "install"

      # Create cpp, gcc and g++ symlinks
      bin.install_symlink "cpp-#{version_suffix}" => "cpp"
      bin.install_symlink "gcc-#{version_suffix}" => "gcc"
      bin.install_symlink "g++-#{version_suffix}" => "g++"
    end

    # Handle conflicts between GCC formulae and avoid interfering
    # with system compilers.
    # Since GCC 4.8 libffi stuff are no longer shipped.
    # Rename man7.
    Dir.glob(man7/"*.7") { |file| add_suffix file, version_suffix }
    # Even when suffixes are appended, the info pages conflict when
    # install-info is run. TODO fix this.
    info.rmtree

    # Move lib64/* to lib/ on Linuxbrew
    lib64 = Pathname.new "#{lib}64"
    if lib64.directory?
      system "mv #{lib64}/* #{lib}/" # Do not use FileUtils.mv with Ruby 1.9.3
      rmdir lib64
      prefix.install_symlink "lib" => "lib64"
    end

    system("strip", "--strip-unneeded", "--preserve-dates", *Dir["#{prefix}/**/*"].select do |f|
      f = Pathname.new(f)
      f.file? && (f.elf? || f.extname == ".a")
    end)
  end

  def add_suffix(file, suffix)
    dir = File.dirname(file)
    ext = File.extname(file)
    base = File.basename(file, ext)
    File.rename file, "#{dir}/#{base}-#{suffix}#{ext}"
  end

  def post_install
    # Create cc and c++ symlinks, unless they already exist
    homebrew_bin = Pathname.new "#{HOMEBREW_PREFIX}/bin"
    homebrew_bin.install_symlink "gcc" => "cc" unless (homebrew_bin/"cc").exist?
    homebrew_bin.install_symlink "g++" => "c++" unless (homebrew_bin/"c++").exist?

    # Create the GCC specs file
    # See https://gcc.gnu.org/onlinedocs/gcc/Spec-Files.html

    # Locate the specs file
    gcc = "gcc-#{version_suffix}"
    specs = Pathname.new(`#{bin}/#{gcc} -print-libgcc-file-name`).dirname/"specs"
    ohai "Creating the GCC specs file: #{specs}"
    raise "command failed: #{gcc} -print-libgcc-file-name" if $?.exitstatus != 0
    specs_orig = Pathname.new("#{specs}.orig")
    rm_f [specs_orig, specs]

    # Save a backup of the default specs file
    specs_string = `#{bin}/#{gcc} -dumpspecs`
    raise "command failed: #{gcc} -dumpspecs" if $?.exitstatus != 0
    specs_orig.write specs_string

    # Set the library search path
    # This should be the default_prefix since we expect an ABI => C runtime
    # to be available and backward compatible on the system.
    glibc = Formula["glibc-legacy"]
    libgcc = lib/"gcc/x86_64-unknown-linux-gnu"/version
    specs.write specs_string + <<~EOS
      *link_libgcc:
      #{glibc.installed? ? "-nostdlib -L#{libgcc}" : "+"} -L#{legacy_prefix}/lib -L#{default_prefix}/lib -lrt -lpthread

      *link:
      + --dynamic-linker #{legacy_prefix}/lib/ld-linux-x86-64.so.2 -rpath #{default_prefix}/lib

    EOS
  end
end
