require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Gcc < AbstractOsqueryFormula
  desc "GNU compiler collection"
  homepage "https://gcc.gnu.org"
  url "https://ftp.heanet.ie/mirrors/gnu/gcc/gcc-5.3.0/gcc-5.3.0.tar.bz2"
  mirror "https://ftp.gnu.org/gnu/gcc/gcc-5.3.0/gcc-5.3.0.tar.bz2"
  sha256 "b84f5592e9218b73dbae612b5253035a7b34a9a1f7688d2e1bfaaf7267d5c4db"
  revision 1

  head "svn://gcc.gnu.org/svn/gcc/trunk"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "d7c052f743e13ce26def4a1eb084cc4f915a39b54e9dfa09f23e7bd8a95d794b" => :x86_64_linux
  end

  option "with-java", "Build the gcj compiler"
  option "with-all-languages", "Enable all compilers and languages, except Ada"
  option "with-nls", "Build with native language support (localization)"
  option "with-jit", "Build the jit compiler"
  option "with-fortran", "Build without the gfortran compiler"
  option "with-multilib", "Build with multilib support"

  depends_on "zlib" unless OS.mac?
  depends_on "binutils" if build.with? "glibc"
  depends_on "gmp"
  depends_on "libmpc"
  depends_on "mpfr"
  depends_on "isl"

  fails_with :gcc_4_0
  fails_with :llvm

  # GCC bootstraps itself, so it is OK to have an incompatible C++ stdlib
  cxxstdlib_check :skip

  def version_suffix
    version.to_s.slice(/\d/)
  end

  def osmajor
    `uname -r`.chomp
  end

  def install
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
      "--with-gmp=#{default_prefix}/opt/gmp",
      "--with-mpfr=#{default_prefix}/opt/mpfr",
      "--with-mpc=#{default_prefix}/opt/libmpc",
      "--with-isl=#{default_prefix}/opt/isl",
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
    args << "--with-boot-ldflags=-static-libstdc++ -static-libgcc #{ENV["LDFLAGS"]}" if OS.linux?

    # "Building GCC with plugin support requires a host that supports
    # -fPIC, -shared, -ldl and -rdynamic."
    args << "--enable-plugin"

    # The pre-Mavericks toolchain requires the older DWARF-2 debugging data
    # format to avoid failure during the stage 3 comparison of object files.
    # See: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=45248
    args << "--with-dwarf2" if OS.mac? && MacOS.version <= :mountain_lion
    args << "--disable-nls" if build.without? "nls"
    args << "--disable-multilib"

    # Ensure correct install names when linking against libgcc_s;
    # see discussion in https://github.com/Homebrew/homebrew/pull/34303
    inreplace "libgcc/config/t-slibgcc-darwin", "@shlib_slibdir@", "#{default_prefix}/lib/gcc/#{version_suffix}"
    inreplace "libitm/method-serial.cc", "assert (ok);", "(void) ok;"

    ENV.delete "LDFLAGS"
    ENV.delete "LD_LIBRARY_PATH"

    # osquery: speed up the build by skipping the bootstrap.
    args << "--disable-bootstrap"
    args << "--disable-libgomp"

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

    # Rename java properties
    if build.with?("java") || build.with?("all-languages")
      config_files = [
        "#{lib}/gcc/#{version_suffix}/logging.properties",
        "#{lib}/gcc/#{version_suffix}/security/classpath.security",
        "#{lib}/gcc/#{version_suffix}/i386/logging.properties",
        "#{lib}/gcc/#{version_suffix}/i386/security/classpath.security",
      ]
      config_files.each do |file|
        add_suffix file, version_suffix if File.exist? file
      end
    end

    # Move lib64/* to lib/ on Linuxbrew
    lib64 = Pathname.new "#{lib}64"
    if lib64.directory?
      system "mv #{lib64}/* #{lib}/" # Do not use FileUtils.mv with Ruby 1.9.3
      rmdir lib64
      prefix.install_symlink "lib" => "lib64"
    end
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
    specs.write specs_string + <<-EOS.undent
      *cpp_unique_options:
      + -isystem #{legacy_prefix}/include

      *link_libgcc:
      #{glibc.installed? ? "-nostdlib -L#{libgcc}" : "+"} -L#{legacy_prefix}/lib -L#{default_prefix}/lib -lrt -lpthread

      *link:
      + --dynamic-linker #{legacy_prefix}/lib/ld-linux-x86-64.so.2 -rpath #{default_prefix}/lib

    EOS
  end

  test do
    (testpath/"hello-c.c").write <<-EOS.undent
      #include <stdio.h>
      int main()
      {
        puts("Hello, world!");
        return 0;
      }
    EOS
    system "#{bin}/gcc-#{version_suffix}", "-o", "hello-c", "hello-c.c"
    assert_equal "Hello, world!\n", `./hello-c`

    (testpath/"hello-cc.cc").write <<-EOS.undent
      #include <iostream>
      int main()
      {
        std::cout << "Hello, world!" << std::endl;
        return 0;
      }
    EOS
    system "#{bin}/g++-#{version_suffix}", "-o", "hello-cc", "hello-cc.cc"
    assert_equal "Hello, world!\n", `./hello-cc`
  end
end
