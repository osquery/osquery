require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Bison < AbstractOsqueryFormula
  desc "Parser generator"
  homepage "https://www.gnu.org/software/bison/"
  url "https://ftp.gnu.org/gnu/bison/bison-3.0.4.tar.gz"
  mirror "https://ftpmirror.gnu.org/bison/bison-3.0.4.tar.gz"
  sha256 "b67fd2daae7a64b5ba862c66c07c1addb9e6b1b05c5f2049392cfd8a2172952e"

  bottle do
    sha256 "609cc77d6ef01c5a7afc2f96b8a27fb7fcb639b3f6192f6e0f8d2f7623cc141e" => :sierra
    sha256 "17488b69156f6fc91dd438c54920751399c23745f330487abd54c4cbcb49ff6a" => :el_capitan
    sha256 "0a6b72564c1602a033d814b68939bf2732f21cfdc06196c29da19c79faba669f" => :yosemite
    sha256 "a3146ea90c2e4ee5d5626154b3446c7c5aea748b9239beac6ac2c26e753c830e" => :mavericks
    sha256 "1ac1b43ae92fea5b04f663197309ce8b788061d31f09ba14e97dd4d5d1183d62" => :mountain_lion
  end

  # Fix crash from usage of %n in dynamic format strings on High Sierra
  # Patch credit to Jeremy Huddleston Sequoia <jeremyhu@apple.com>
  if MacOS.version >= :high_sierra
    patch :p0 do
      url "https://raw.githubusercontent.com/macports/macports-ports/14451f57e89/devel/bison/files/secure_snprintf.patch"
      sha256 "57f972940a10d448efbd3d5ba46e65979ae4eea93681a85e1d998060b356e0d2"
    end
  end

  def install
    system "./configure", "--disable-dependency-tracking",
                          "--prefix=#{prefix}"
    system "make", "install"
  end

  test do
    (testpath/"test.y").write <<-EOS.undent
      %{ #include <iostream>
         using namespace std;
         extern void yyerror (char *s);
         extern int yylex ();
      %}
      %start prog
      %%
      prog:  //  empty
          |  prog expr '\\n' { cout << "pass"; exit(0); }
          ;
      expr: '(' ')'
          | '(' expr ')'
          |  expr expr
          ;
      %%
      char c;
      void yyerror (char *s) { cout << "fail"; exit(0); }
      int yylex () { cin.get(c); return c; }
      int main() { yyparse(); }
    EOS
    system "#{bin}/bison", "test.y"
    system ENV.cxx, "test.tab.c", "-o", "test"
    assert_equal "pass", shell_output("echo \"((()(())))()\" | ./test")
    assert_equal "fail", shell_output("echo \"())\" | ./test")
  end
end