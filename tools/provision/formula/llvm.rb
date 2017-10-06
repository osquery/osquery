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
  revision 101

  stable do
    url "http://releases.llvm.org/4.0.0/llvm-4.0.0.src.tar.xz"
    sha256 "8d10511df96e73b8ff9e7abbfb4d4d432edbdbe965f1f4f07afaf370b8a533be"

    resource "clang" do
      url "http://releases.llvm.org/4.0.0/cfe-4.0.0.src.tar.xz"
      sha256 "cea5f88ebddb30e296ca89130c83b9d46c2d833685e2912303c828054c4dc98a"
    end

    resource "clang-extra-tools" do
      url "http://releases.llvm.org/4.0.0/clang-tools-extra-4.0.0.src.tar.xz"
      sha256 "41b7d37eb128fd362ab3431be5244cf50325bb3bb153895735c5bacede647c99"
    end

    resource "compiler-rt" do
      url "http://releases.llvm.org/4.0.0/compiler-rt-4.0.0.src.tar.xz"
      sha256 "d3f25b23bef24c305137e6b44f7e81c51bbec764c119e01512a9bd2330be3115"
    end

    # Only required to build & run Compiler-RT tests on macOS, optional otherwise.
    # https://clang.llvm.org/get_started.html
    resource "libcxx" do
      url "http://releases.llvm.org/4.0.0/libcxx-4.0.0.src.tar.xz"
      sha256 "4f4d33c4ad69bf9e360eebe6b29b7b19486948b1a41decf89d4adec12473cf96"
    end

    resource "libcxxabi" do
      url "http://llvm.org/releases/4.0.0/libcxxabi-4.0.0.src.tar.xz"
      sha256 "dca9cb619662ad2d3a0d685c4366078345247218c3702dd35bcaaa23f63481d8"
    end

    resource "libunwind" do
      url "http://releases.llvm.org/4.0.0/libunwind-4.0.0.src.tar.xz"
      sha256 "0755efa9f969373d4d543123bbed4b3f9a835f6302875c1379c5745857725973"
    end

    resource "lld" do
      url "http://releases.llvm.org/4.0.0/lld-4.0.0.src.tar.xz"
      sha256 "33e06457b9ce0563c89b11ccc7ccabf9cff71b83571985a5bf8684c9150e7502"
    end

    resource "lldb" do
      url "http://releases.llvm.org/4.0.0/lldb-4.0.0.src.tar.xz"
      sha256 "2dbd8f05c662c1c9f11270fc9d0c63b419ddc988095e0ad107ed911cf882033d"
    end

    resource "openmp" do
      url "http://releases.llvm.org/4.0.0/openmp-4.0.0.src.tar.xz"
      sha256 "db55d85a7bb289804dc42fc5c8e35ca24dfc3885782261b675a194fd7e206e26"
    end

    resource "polly" do
      url "http://releases.llvm.org/4.0.0/polly-4.0.0.src.tar.xz"
      sha256 "27a5dbf95e8aa9e0bbe3d6c5d1e83c92414d734357aa0d6c16020a65dc4dcd97"
    end
  end

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "92a00d9b9b4aad6a7461155aa7a913c6b541436c200b201b240150b76d4c6bd2" => :x86_64_linux
  end

  keg_only :provided_by_osx

  option "without-compiler-rt", "Do not build Clang runtime support libraries for code sanitizers, builtins, and profiling"
  option "with-libcxx", "Build libc++ standard library"
  option "with-toolchain", "Build with Toolchain to facilitate overriding system compiler"
  option "with-lldb", "Build LLDB debugger"
  option "with-python", "Build bindings against custom Python"
  option "with-shared-libs", "Build shared instead of static libraries"
  option "without-libffi", "Do not use libffi to call external functions"

  depends_on "binutils" if build.with? "clang"
  depends_on "cmake" => :build

  needs :cxx11

  def build_libcxx?
    build.with?("libcxx")
  end

  def install
    # Added to gcc's specs, but also needed here.
    ENV.append "LDFLAGS", "-lrt -lpthread"

    # Apple's libstdc++ is too old to build LLVM
    ENV.libcxx if ENV.compiler == :clang

    (buildpath/"tools/clang").install resource("clang")

    # Add glibc to the list of library directories so that we won't have to do -L<path-to-glibc>/lib
    inreplace buildpath/"tools/clang/lib/Driver/ToolChains.cpp",
      "// Add the multilib suffixed paths where they are available.",
      "addPathIfExists(D, \"#{HOMEBREW_PREFIX}/opt/glibc/lib\", Paths);\n\n  // Add the multilib suffixed paths where they are available."

    (buildpath/"tools/clang/tools/extra").install resource("clang-extra-tools")
    (buildpath/"projects/openmp").install resource("openmp")
    (buildpath/"projects/libcxx").install resource("libcxx") if build_libcxx?
    (buildpath/"projects/libcxxabi").install resource("libcxxabi") if build_libcxx?
    (buildpath/"projects/libunwind").install resource("libunwind")
    (buildpath/"tools/lld").install resource("lld")
    (buildpath/"tools/polly").install resource("polly")

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
      -DLLVM_OPTIMIZED_TABLEGEN=ON
      -DLLVM_INCLUDE_DOCS=OFF
      -DLLVM_ENABLE_RTTI=ON
      -DLLVM_ENABLE_EH=ON
      -DLLVM_INSTALL_UTILS=ON
      -DWITH_POLLY=ON
      -DLINK_POLLY_INTO_TOOLS=ON
      -DLLVM_TARGETS_TO_BUILD=all
    ]

    # osquery added a link for pthread
    args << "-DLIBOMP_LIBFLAGS=-lpthread" # Fails to link libgomp

    args << "-DLIBOMP_ARCH=x86_64"
    args << "-DLLVM_BUILD_EXTERNAL_COMPILER_RT=ON" if build.with? "compiler-rt"
    args << "-DLLVM_BUILD_LLVM_DYLIB=ON"

    if build.with? "rtti"
      args << "-DLLVM_ENABLE_RTTI=ON"
      args << "-DLLVM_ENABLE_EH=ON"
    end

    args << "-DLLVM_ENABLE_LIBCXX=ON" if build_libcxx?
    args << "-DLLVM_ENABLE_LIBCXXABI=ON" if build_libcxx? && !OS.mac?

    # Enable llvm gold plugin for LTO
    args << "-DLLVM_BINUTILS_INCDIR=#{Formula["binutils"].opt_include}"

    gccpref = Formula["gcc"].opt_prefix.to_s
    args << "-DGCC_INSTALL_PREFIX=#{gccpref}"
    args << "-DCMAKE_C_COMPILER=#{gccpref}/bin/gcc"
    args << "-DCMAKE_CXX_COMPILER=#{gccpref}/bin/g++"
    args << "-DCMAKE_CXX_LINK_FLAGS=-L#{gccpref}/lib64 -Wl,-rpath,#{gccpref}/lib64"
    args << "-DCLANG_DEFAULT_CXX_STDLIB=#{build.with?("libcxx") ? "libc++" : "libstdc++"}"

    mktemp do
      system "cmake", "-G", "Unix Makefiles", buildpath, *(std_cmake_args + args)
      system "make", "-j#{ENV.make_jobs}"
      system "make", "install"
    end

    (share/"clang/tools").install Dir["tools/clang/tools/scan-{build,view}"]
    inreplace "#{share}/clang/tools/scan-build/bin/scan-build", "$RealBin/bin/clang", "#{bin}/clang"
    bin.install_symlink share/"clang/tools/scan-build/bin/scan-build", share/"clang/tools/scan-view/bin/scan-view"
    man1.install_symlink share/"clang/tools/scan-build/man/scan-build.1"

    # install llvm python bindings
    (lib/"python2.7/site-packages").install buildpath/"bindings/python/llvm"
    (lib/"python2.7/site-packages").install buildpath/"tools/clang/bindings/python/clang"

    rm [lib/"libgomp.so", lib/"libunwind.so"]
  end

  def caveats
    if build_libcxx?
      <<-EOS.undent
        To use the bundled libc++ please add the following LDFLAGS:
          LDFLAGS="-L#{opt_lib} -Wl,-rpath,#{opt_lib}"
      EOS
    end
  end

  test do
    assert_equal prefix.to_s, shell_output("#{bin}/llvm-config --prefix").chomp

    if build.with? "clang"
      (testpath/"test.cpp").write <<-EOS.undent
        #include <iostream>

        int main()
        {
          std::cout << "Hello World!" << std::endl;
          return 0;
        }
      EOS
      system "#{bin}/clang++", "test.cpp", "-o", "test"
      system "./test"
    end
  end
end
