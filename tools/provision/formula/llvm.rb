require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Llvm < AbstractOsqueryFormula
  desc "Next-gen compiler infrastructure"
  homepage "http://llvm.org/"
  license "NCSA"
  revision 200

  stable do
    url "http://releases.llvm.org/#{llvm_version}/llvm-#{llvm_version}.src.tar.xz"
    sha256 "5fa7489fc0225b11821cab0362f5813a05f2bcf2533e8a4ea9c9c860168807b0"

    resource "clang" do
      url "http://releases.llvm.org/#{llvm_version}/cfe-#{llvm_version}.src.tar.xz"
      sha256 "135f6c9b0cd2da1aff2250e065946258eb699777888df39ca5a5b4fe5e23d0ff"
    end

    resource "clang-extra-tools" do
      url "http://releases.llvm.org/#{llvm_version}/clang-tools-extra-#{llvm_version}.src.tar.xz"
      sha256 "9aada1f9d673226846c3399d13fab6bba4bfd38bcfe8def5ee7b0ec24f8cd225"
    end

    resource "lld" do
      url "http://releases.llvm.org/#{llvm_version}/lld-#{llvm_version}.src.tar.xz"
      sha256 "d5b36c0005824f07ab093616bdff247f3da817cae2c51371e1d1473af717d895"
    end

    resource "lldb" do
      url "http://releases.llvm.org/#{llvm_version}/lldb-#{llvm_version}.src.tar.xz"
      sha256 "b7c1c9e67975ca219089a3a6a9c77c2d102cead2dc38264f2524aa3326da376a"
    end

    resource "openmp" do
      url "http://releases.llvm.org/#{llvm_version}/openmp-#{llvm_version}.src.tar.xz"
      sha256 "adb635cdd2f9f828351b1e13d892480c657fb12500e69c70e007bddf0fca2653"
    end

    resource "polly" do
      url "http://releases.llvm.org/#{llvm_version}/polly-#{llvm_version}.src.tar.xz"
      sha256 "9dd52b17c07054aa8998fc6667d41ae921430ef63fa20ae130037136fdacf36e"
    end
  end

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "ada916f175f62e8ed5f5c7630edb5783d927e20989f0d6c843c66bde1d863e2d" => :x86_64_linux
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
