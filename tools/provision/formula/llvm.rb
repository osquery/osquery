require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class CodesignRequirement < Requirement
  include FileUtils
  fatal true

  satisfy(:build_env => false) do
    mktemp do
      cp "/usr/bin/false", "llvm_check"
      quiet_system "/usr/bin/codesign", "-f", "-s", "lldb_codesign", "--dryrun", "llvm_check"
    end
  end

  def message
    <<-EOS.undent
      lldb_codesign identity must be available to build with LLDB.
      See: https://llvm.org/svn/llvm-project/lldb/trunk/docs/code-signing.txt
    EOS
  end
end

class Llvm < AbstractOsqueryFormula
  desc "Next-gen compiler infrastructure"
  homepage "http://llvm.org/"
  revision 2

  stable do
    url "http://llvm.org/releases/3.8.1/llvm-3.8.1.src.tar.xz"
    sha256 "6e82ce4adb54ff3afc18053d6981b6aed1406751b8742582ed50f04b5ab475f9"

    resource "clang" do
      url "http://llvm.org/releases/3.8.1/cfe-3.8.1.src.tar.xz"
      sha256 "4cd3836dfb4b88b597e075341cae86d61c63ce3963e45c7fe6a8bf59bb382cdf"
    end

    resource "clang-extra-tools" do
      url "http://llvm.org/releases/3.8.1/clang-tools-extra-3.8.1.src.tar.xz"
      sha256 "664a5c60220de9c290bf2a5b03d902ab731a4f95fe73a00856175ead494ec396"
    end

    resource "compiler-rt" do
      url "http://llvm.org/releases/3.8.1/compiler-rt-3.8.1.src.tar.xz"
      sha256 "0df011dae14d8700499dfc961602ee0a9572fef926202ade5dcdfe7858411e5c"
    end

    resource "polly" do
      url "http://llvm.org/releases/3.8.1/polly-3.8.1.src.tar.xz"
      sha256 "453c27e1581614bb3b6351bf5a2da2939563ea9d1de99c420f85ca8d87b928a2"
    end
  end

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "413eb81e07ea61bc3dc99ecb95fa4fce9cd087080259b342a0b3f7f1fe4808c8" => :x86_64_linux
  end

  head do
    url "http://llvm.org/git/llvm.git"

    resource "clang" do
      url "http://llvm.org/git/clang.git"
    end

    resource "clang-extra-tools" do
      url "http://llvm.org/git/clang-tools-extra.git"
    end

    resource "compiler-rt" do
      url "http://llvm.org/git/compiler-rt.git"
    end

    resource "polly" do
      url "http://llvm.org/git/polly.git"
    end
  end

  keg_only :provided_by_osx

  option :universal
  option "without-clang", "Build the Clang compiler and support libraries"
  option "without-clang-extra-tools", "Build extra tools for Clang"
  option "without-compiler-rt", "Build Clang runtime support libraries for code sanitizers, builtins, and profiling"
  option "without-rtti", "Build with C++ RTTI"
  option "without-utils", "Install utility binaries"
  option "without-polly", "Do not build Polly optimizer"

  deprecated_option "rtti" => "with-rtti"

  depends_on "binutils" if build.with? "clang"

  # Apple's libstdc++ is too old to build LLVM
  fails_with :gcc
  fails_with :llvm

  def install
    # Added to gcc's specs, but also needed here.
    ENV.append "LDFLAGS", "-lrt -lpthread"

    # Apple's libstdc++ is too old to build LLVM
    ENV.libcxx if ENV.compiler == :clang

    (buildpath/"tools/clang").install resource("clang") if build.with? "clang"
    (buildpath/"tools/clang/tools/extra").install resource("clang-extra-tools")
    (buildpath/"tools/polly").install resource("polly") if build.with? "polly"

    if build.with? "compiler-rt"
      (buildpath/"projects/compiler-rt").install resource("compiler-rt")

      # compiler-rt has some iOS simulator features that require i386 symbols
      # I'm assuming the rest of clang needs support too for 32-bit compilation
      # to work correctly, but if not, perhaps universal binaries could be
      # limited to compiler-rt. llvm makes this somewhat easier because compiler-rt
      # can almost be treated as an entirely different build from llvm.
      ENV.permit_arch_flags
    end

    args = %w[
      -DLLVM_OPTIMIZED_TABLEGEN=On
      -DLLVM_BUILD_LLVM_DYLIB=On
    ]

    if build.with? "rtti"
      args << "-DLLVM_ENABLE_RTTI=ON"
      args << "-DLLVM_ENABLE_EH=ON"
    end

    if build.with? "clang"
      # build the LLVMGold plugin
      binutils = Formula["binutils"].prefix/"include"
      args << "-DLLVM_BINUTILS_INCDIR=#{binutils}"
    end

    args << "-DLLVM_BUILD_EXTERNAL_COMPILER_RT=ON" if build.with? "compiler-rt"
    args << "-DLLVM_INSTALL_UTILS=On" if build.with? "utils"
    args << "-DGCC_INSTALL_PREFIX=#{Formula["gcc"].prefix}"

    if build.universal?
      ENV.permit_arch_flags
      args << "-DCMAKE_OSX_ARCHITECTURES=#{Hardware::CPU.universal_archs.as_cmake_arch_flags}"
    end

    if build.with? "polly"
      args << "-DWITH_POLLY=ON"
      args << "-DLINK_POLLY_INTO_TOOLS=ON"
    end

    mktemp do
      system "cmake", "-G", "Unix Makefiles", buildpath, *(std_cmake_args + args)
      system "make"
      system "make", "install"
    end

    (share/"clang/tools").install Dir["tools/clang/tools/scan-{build,view}"]
    inreplace "#{share}/clang/tools/scan-build/bin/scan-build", "$RealBin/bin/clang", "#{bin}/clang"
    bin.install_symlink share/"clang/tools/scan-build/bin/scan-build", share/"clang/tools/scan-view/bin/scan-view"
    man1.install_symlink share/"clang/tools/scan-build/man/scan-build.1"

    # install llvm python bindings
    (lib/"python2.7/site-packages").install buildpath/"bindings/python/llvm"
    (lib/"python2.7/site-packages").install buildpath/"tools/clang/bindings/python/clang"
  end

  def caveats
    s = <<-EOS.undent
      LLVM executables are installed in #{opt_bin}.
      Extra tools are installed in #{opt_share}/llvm.
    EOS

    if build.with? "libcxx"
      s += <<-EOS.undent
        To use the bundled libc++ please add the following LDFLAGS:
          LDFLAGS="-L#{opt_lib} -lc++abi"
      EOS
    end

    s
  end

  test do
    assert_equal prefix.to_s, shell_output("#{bin}/llvm-config --prefix").chomp

    if build.with? "clang"
      (testpath/"test.cpp").write <<-EOS.undent
        #include <iostream>
        using namespace std;

        int main()
        {
          cout << "Hello World!" << endl;
          return 0;
        }
      EOS
      system "#{bin}/clang++", "test.cpp", "-o", "test"
      system "./test"
    end
  end
end
