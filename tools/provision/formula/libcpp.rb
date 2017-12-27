require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libcpp < AbstractOsqueryFormula
  desc "Next-gen compiler infrastructure"
  homepage "http://llvm.org/"
  license "NCSA"
  revision 200

  stable do
    url "http://releases.llvm.org/#{llvm_version}/llvm-#{llvm_version}.src.tar.xz"
    sha256 "5fa7489fc0225b11821cab0362f5813a05f2bcf2533e8a4ea9c9c860168807b0"

    # Only required to build & run Compiler-RT tests on macOS, optional otherwise.
    # https://clang.llvm.org/get_started.html
    resource "libcxx" do
      url "http://releases.llvm.org/#{llvm_version}/libcxx-#{llvm_version}.src.tar.xz"
      sha256 "fa8f99dd2bde109daa3276d529851a3bce5718d46ce1c5d0806f46caa3e57c00"
    end

    resource "clang" do
      url "http://releases.llvm.org/#{llvm_version}/cfe-#{llvm_version}.src.tar.xz"
      sha256 "135f6c9b0cd2da1aff2250e065946258eb699777888df39ca5a5b4fe5e23d0ff"
    end

    resource "libcxxabi" do
      url "http://llvm.org/releases/#{llvm_version}/libcxxabi-#{llvm_version}.src.tar.xz"
      sha256 "5a25152cb7f21e3c223ad36a1022faeb8a5ac27c9e75936a5ae2d3ac48f6e854"
    end

    resource "compiler-rt" do
      url "http://releases.llvm.org/#{llvm_version}/compiler-rt-#{llvm_version}.src.tar.xz"
      sha256 "4edd1417f457a9b3f0eb88082530490edf3cf6a7335cdce8ecbc5d3e16a895da"
    end

    resource "libunwind" do
      url "http://releases.llvm.org/#{llvm_version}/libunwind-#{llvm_version}.src.tar.xz"
      sha256 "6bbfbf6679435b858bd74bdf080386d084a76dfbf233fb6e47b2c28e0872d0fe"
    end
  end

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "068bf3beabbb71f4ba62e5e52abddbc30acb829374a28d3e1440c3135b0d3b24" => :x86_64_linux
  end

  depends_on "binutils"
  depends_on "cmake" => :build

  needs :cxx11

  def clang_lib
    return "#{Formula["osquery/osquery-local/llvm"].prefix}/lib/clang/#{llvm_version}/lib"
  end

  def install
    (buildpath/"tools/clang").install resource("clang")
    (buildpath/"projects/compiler-rt").install resource("compiler-rt")
    (buildpath/"projects/libcxx").install resource("libcxx")
    (buildpath/"projects/libcxxabi").install resource("libcxxabi")
    (buildpath/"projects/libunwind").install resource("libunwind")

    # Building with Shared libs, could use LIBNAME_ENABLE_SHARED=NO.
    args = %w[
      -DLLVM_OPTIMIZED_TABLEGEN=ON
      -DLLVM_INCLUDE_DOCS=OFF
      -DLLVM_ENABLE_RTTI=ON
      -DLLVM_ENABLE_EH=ON
      -DLLVM_TARGETS_TO_BUILD=X86;ARM;AArch64
      -DLLVM_INCLUDE_EXAMPLES=OFF
      -DLLVM_INCLUDE_TESTS=OFF
      -DLIBCXX_USE_COMPILER_RT=ON
      -DLIBCXXABI_USE_COMPILER_RT=ON
      -DLIBCXXABI_USE_LLVM_UNWINDER=ON
      -DLLVM_BUILD_EXTERNAL_COMPILER_RT=ON
      -DCLANG_DEFAULT_CXX_STDLIB=libstdc++
    ]

    mktemp do
      system "cmake", "-G", "Unix Makefiles", buildpath/"projects/compiler-rt", *(std_cmake_args + args)
      system "make"
      system "make", "install"
    end

    mktemp do
      system "cmake", "-G", "Unix Makefiles", buildpath, *(std_cmake_args + args)
      cd "projects" do
        system "make", "-j#{ENV.make_jobs}"
        system "make", "install"
      end
    end

    ln_sf prefix/"lib", clang_lib
  end
end
