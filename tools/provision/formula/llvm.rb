require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Llvm < AbstractOsqueryFormula
  desc "Next-gen compiler infrastructure"
  homepage "http://llvm.org/"
  license "NCSA"
  revision 200

  stable do
    url "http://releases.llvm.org/#{llvm_version}/llvm-#{llvm_version}.src.tar.xz"
    sha256 "1ff53c915b4e761ef400b803f07261ade637b0c269d99569f18040f3dcee4408"

    resource "clang" do
      url "http://releases.llvm.org/#{llvm_version}/cfe-#{llvm_version}.src.tar.xz"
      sha256 "e07d6dd8d9ef196cfc8e8bb131cbd6a2ed0b1caf1715f9d05b0f0eeaddb6df32"
    end

    resource "clang-extra-tools" do
      url "http://releases.llvm.org/#{llvm_version}/clang-tools-extra-#{llvm_version}.src.tar.xz"
      sha256 "053b424a4cd34c9335d8918734dd802a8da612d13a26bbb88fcdf524b2d989d2"
    end

    resource "lld" do
      url "http://releases.llvm.org/#{llvm_version}/lld-#{llvm_version}.src.tar.xz"
      sha256 "6b8c4a833cf30230c0213d78dbac01af21387b298225de90ab56032ca79c0e0b"
    end

    resource "lldb" do
      url "http://releases.llvm.org/#{llvm_version}/lldb-#{llvm_version}.src.tar.xz"
      sha256 "46f54c1d7adcd047d87c0179f7b6fa751614f339f4f87e60abceaa45f414d454"
    end

    resource "openmp" do
      url "http://releases.llvm.org/#{llvm_version}/openmp-#{llvm_version}.src.tar.xz"
      sha256 "7c0e050d5f7da3b057579fb3ea79ed7dc657c765011b402eb5bbe5663a7c38fc"
    end

    resource "polly" do
      url "http://releases.llvm.org/#{llvm_version}/polly-#{llvm_version}.src.tar.xz"
      sha256 "47e493a799dca35bc68ca2ceaeed27c5ca09b12241f87f7220b5f5882194f59c"
    end
  end

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "54ff9c6b305defdc34408abe1c446f2fd7f3645e415833d80e16c4a1bab65564" => :x86_64_linux
  end

  depends_on "cmake" => :build

  needs :cxx11

  def build_libcxx?
    build.with?("libcxx")
  end

  def install
    # Added to gcc's specs, but also needed here.
    ENV.append "LDFLAGS", "-lrt -lpthread"

    (buildpath/"tools/clang").install resource("clang")
    (buildpath/"tools/clang/tools/extra").install resource("clang-extra-tools")
    (buildpath/"projects/openmp").install resource("openmp")
    (buildpath/"tools/lld").install resource("lld")
    (buildpath/"tools/polly").install resource("polly")

    args = %w[
      -DLLVM_OPTIMIZED_TABLEGEN=ON
      -DLLVM_INCLUDE_DOCS=OFF
      -DLLVM_ENABLE_RTTI=ON
      -DLLVM_ENABLE_EH=ON
      -DLLVM_INSTALL_UTILS=ON
      -DWITH_POLLY=ON
      -DLINK_POLLY_INTO_TOOLS=ON
      -DLLVM_TARGETS_TO_BUILD=X86;ARM;AArch64
      -DLLVM_BUILD_LLVM_DYLIB=ON
      -DBUILD_SHARED_LIBS=OFF
      -DLLVM_LINK_LLVM_DYLIB=ON
    ]

    # osquery added a link for pthread
    args << "-DLIBOMP_LIBFLAGS=-lpthread" # Fails to link libgomp
    args << "-DLIBOMP_ARCH=x86_64"

    gccpref = Formula["gcc"].opt_prefix.to_s
    args << "-DGCC_INSTALL_PREFIX=#{gccpref}"
    args << "-DCMAKE_C_COMPILER=#{gccpref}/bin/gcc"
    args << "-DCMAKE_CXX_COMPILER=#{gccpref}/bin/g++"
    args << "-DCMAKE_CXX_LINK_FLAGS=-L#{gccpref}/lib64 -Wl,-rpath,#{gccpref}/lib64"
    args << "-DCLANG_DEFAULT_CXX_STDLIB=libstdc++"

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

    rm [lib/"libgomp.so"]
  end
end
