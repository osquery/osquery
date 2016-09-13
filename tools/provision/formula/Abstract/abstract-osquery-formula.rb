require "formula"
require "extend/ENV/shared"

module SkipRelocation
  def skip_relocation?
    true
  end
end

class AbstractOsqueryFormula < Formula
  def initialize(*)
    super

    # Inject a forced-skipped-relocation to support multiple runtimes.
    # At build/compile time the formula will choose the active runtime to link
    # against, this *should* remain during bottle generation and pouring.
    bottle_specification.extend(SkipRelocation)
  end

  def setup
    @setup = ENV.has_key?('ABSTRACT_OSQUERY_FORMULA')
    ENV['ABSTRACT_OSQUERY_FORMULA'] = '1'
    return @setup
  end

  def reset(name)
    ENV.delete name
  end

  def append(name, value)
    ENV[name] = ENV.has_key?(name) ? ENV[name] + ' ' + value.to_s : value.to_s
  end

  def prepend(name, value)
    ENV[name] = ENV.has_key?(name) ? value.to_s + ' ' + ENV[name] : value.to_s
  end

  def prepend_path(name, value)
    ENV[name] = ENV.has_key?(name) ? value.to_s + ':' + ENV[name] : value.to_s
  end

  def self.method_added(name)
    return unless /install/.match(name.to_s)
    return if /inject/.match(name.to_s)
    return if /hook/.match(name.to_s) or method_defined?("#{name}_hook_target")

    hook = "def #{name}_hook\n setup_inject\n #{name}_hook_target\nend"
    self.class_eval(hook)
    target = "alias #{name}_hook_target #{name}"
    self.class_eval(target)
    inject_hook = "alias #{name} #{name}_hook"
    self.class_eval(inject_hook)
  end

  def legacy
    return Formula["glibc-legacy"]
  end

  def modern
    return Formula["glibc"]
  end

  def setup_inject
    return if setup

    puts "Hello from setup osquery: #{name}"

    # Reset compile flags for safety, we want to control them explicitly.
    reset "CFLAGS"
    reset "CXXFLAGS"

    # Reset the following since the logic within the 'std' environment does not
    # known about our legacy runtime 'glibc' formula name.
    reset "LDFLAGS"
    reset "LD_LIBRARY_PATH"
    reset "LD_RUN_PATH"
    reset "CPATH"
    reset "LIBRARY_PATH"

    if OS.linux? && !["glibc", "glibc-legacy"].include?(self.name)
      # The modern runtime is not brew-linked.

      prepend_path "LD_LIBRARY_PATH", lib
      prepend_path "LD_LIBRARY_PATH", prefix

      # Set the dynamic linker and library search path.
      prepend "CFLAGS", "-isystem#{HOMEBREW_PREFIX}/include"

      # clang wants -L in the CFLAGS.
      # Several projects do not want this: pcre, RocksDB
      # These used to belong to !gcc but -lz wants the system libz.
      prepend "CFLAGS", "-L#{HOMEBREW_PREFIX}/lib"
      prepend "CFLAGS", "-L#{legacy.lib}"

      # cmake wants this to have -I
      prepend "CXXFLAGS", "-I#{HOMEBREW_PREFIX}/include"
      prepend "CXXFLAGS", "-I#{legacy.include}"

      # This used to be in the GCC/not-GCC logic, pulling out to compile GCC
      # Using the system compilers with legacy runtime.
      prepend "CFLAGS", "-isystem#{legacy.include}"
      prepend "CXXFLAGS", "-isystem#{legacy.include}"

      append "LDFLAGS", "-Wl,--dynamic-linker=#{legacy.lib}/ld-linux-x86-64.so.2"
      append "LDFLAGS", "-Wl,-rpath,#{legacy.lib}"

      # Add a runtime search path for the legacy C implementation.
      append "LDFLAGS", "-Wl,-rpath,#{HOMEBREW_PREFIX}/lib"
      # Adding this one line to help gcc too.
      append "LDFLAGS", "-L#{HOMEBREW_PREFIX}/lib"
      # We want the legacy path to be the last thing prepended.
      prepend "LDFLAGS", "-L#{legacy.lib}"

      prepend_path "LIBRARY_PATH", HOMEBREW_PREFIX/"lib"
      prepend_path "LIBRARY_PATH", legacy.lib

      # This is already set to the PREFIX
      prepend_path "LD_RUN_PATH", HOMEBREW_PREFIX/"lib"

      # Set the search path for header files.
      prepend_path "CPATH", HOMEBREW_PREFIX/"include"
    end

    if !OS.linux?
      prepend_path "PATH", HOMEBREW_PREFIX/"bin"
    end

    # Everyone receives:
    append "CFLAGS", "-fPIC -DNDEBUG -Os -march=core2"
    append "CXXFLAGS", "-fPIC -DNDEBUG -Os -march=core2"

    self.audit
    reset "DEBUG"
  end

  def audit
    return if !ENV.has_key?("DEBUG")
    puts ":: PATH    : " + ENV["PATH"].to_s
    puts ":: CFLAGS  : " + ENV["CFLAGS"].to_s
    puts ":: CPPFLAGS: " + ENV["CPPFLAGS"].to_s
    puts ":: CXXFLAGS: " + ENV["CXXFLAGS"].to_s
    puts ":: LDFLAGS : " + ENV["LDFLAGS"].to_s
    puts ":: CC      : " + ENV["CC"].to_s
    puts ":: CXX     : " + ENV["CXX"].to_s
    puts ""
    puts ":: CPATH           : " + ENV["CPATH"].to_s
    puts ":: LD_LIBRARY_PATH : " + ENV["LD_LIBRARY_PATH"].to_s
    puts ":: LIBRARY_PATH    : " + ENV["LIBRARY_PATH"].to_s
    puts ":: LD_RUN_PATH     : " + ENV["LD_RUN_PATH"].to_s
  end
end
