require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class ClangFormat < AbstractOsqueryFormula
  desc "Formatting tools for C, C++, Obj-C, Java, JavaScript, TypeScript"
  homepage "https://clang.llvm.org/docs/ClangFormat.html"
  version "2018-04-24"
  url "https://llvm.org/svn/llvm-project/llvm/tags/google/stable/2018-04-24/", :using => :svn

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "d45589054615e47aca8acc51c84c484a8b3428a3d89079aa19457c3cae475653" => :high_sierra
  end

  depends_on "cmake" => :build
  depends_on "ninja" => :build
  depends_on "subversion" => :build

  def install
    (buildpath/"projects/libcxx").install resource("libcxx")
    (buildpath/"tools/clang").install resource("clang")

    mkdir "build" do
      args = std_cmake_args
      args << "-DCMAKE_OSX_SYSROOT=/" unless MacOS::Xcode.installed?
      args << "-DLLVM_ENABLE_LIBCXX=ON"
      args << ".."
      system "cmake", "-G", "Ninja", *args
      system "ninja", "clang-format"
      bin.install "bin/clang-format"
    end
    bin.install "tools/clang/tools/clang-format/git-clang-format"
    (share/"clang").install Dir["tools/clang/tools/clang-format/clang-format*"]
  end

  test do
    # NB: below C code is messily formatted on purpose.
    (testpath/"test.c").write <<~EOS
      int         main(char *args) { \n   \t printf("hello"); }
    EOS

    assert_equal "int main(char *args) { printf(\"hello\"); }\n",
        shell_output("#{bin}/clang-format -style=Google test.c")
  end
end
