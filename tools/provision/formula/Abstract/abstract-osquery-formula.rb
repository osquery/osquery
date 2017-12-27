require "formula"
require "extend/ENV/shared"

module SkipRelocation
  def skip_relocation?
    true
  end
end

def llvm_version
  return "5.0.1"
end

def legacy_prefix
  Pathname.new("#{ENV["HOMEBREW_PREFIX"]}/legacy")
end

def default_prefix
  Pathname.new(ENV["HOMEBREW_PREFIX"])
end

def glib_prefix
  Pathname.new(Formula["osquery/osquery-local/glibc-legacy"].prefix)
end

class AbstractOsqueryFormula < Formula
  protected

  class << self
    def set_legacy
      Object.const_set(
        "HOMEBREW_PREFIX",
        legacy_prefix
      )
    end

    def license(name)
      ENV["LICENSE"] = name
    end
  end

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

  def osquery_cmake_args
    includes = "#{default_prefix}/include"
    includes = "#{legacy_prefix}/include:#{includes}" if OS.linux?

    std_cmake_args + [
      "-DCMAKE_LIBRARY_PATH=#{ENV["LIBRARY_PATH"]}",
      "-DCMAKE_INCLUDE_PATH=#{includes}",
    ]
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

  def libc_build
    return ["glibc", "glibc-legacy"].include?(self.name)
  end

  def stage1_build
    return ["gcc"].include?(self.name)
  end

  def stage2_build
    return ["llvm", "zlib-legacy"].include?(self.name)
  end

  def runtime_build
    return ENV["CC"].to_s.include?("clang")
  end

  def libcpp_build
    return ["libcpp"].include?(self.name)
  end

  def setup_runtimes
    prepend_path "LD_LIBRARY_PATH", lib
    prepend_path "LD_LIBRARY_PATH", prefix
    prepend_path "LIBRARY_PATH", "#{default_prefix}/lib"

    if stage1_build
      prepend "CFLAGS", "-isystem#{legacy_prefix}/include" if OS.linux?
      prepend "CXXFLAGS", "-I#{legacy_prefix}/include" if OS.linux?
      prepend "CXXFLAGS", "-isystem#{legacy_prefix}/include" if OS.linux?
      append "CFLAGS", "-Os"
      append "CXXFLAGS", "-Os"
    end

    if stage2_build
      prepend "CFLAGS", "-isystem#{default_prefix}/include"
      prepend "CFLAGS", "-isystem#{legacy_prefix}/include" if OS.linux?
      prepend "CXXFLAGS", "-I#{default_prefix}/include"
      prepend "CXXFLAGS", "-I#{legacy_prefix}/include" if OS.linux?
      prepend "CXXFLAGS", "-isystem#{legacy_prefix}/include" if OS.linux?
      append "CFLAGS", "-Os"
      append "CXXFLAGS", "-Os"
    end

    if runtime_build
      # RapidJSON does not use CPPFlags.
      prepend "CXXFLAGS", "-isystem#{default_prefix}/lib/clang/#{llvm_version}/include" if OS.linux?
      prepend "CXXFLAGS", "-isystem#{default_prefix}/include"
      prepend "CXXFLAGS", "-isystem#{legacy_prefix}/include" if OS.linux?
      prepend "CXXFLAGS", "-isystem#{default_prefix}/include/c++/v1" if OS.linux?

      prepend "CFLAGS", "-isystem#{default_prefix}/lib/clang/#{llvm_version}/include" if OS.linux?
      prepend "CFLAGS", "-isystem#{default_prefix}/include"
      prepend "CFLAGS", "-isystem#{legacy_prefix}/include" if OS.linux?

      if !libcpp_build
        # Clang will place -I before the -isystem from CPPFlags.
        prepend "CXXFLAGS", "-I#{default_prefix}/include/c++/v1" if OS.linux?
        append "CXXFLAGS", "-stdlib=libc++" if OS.linux?
        append "LDFLAGS", "-rtlib=compiler-rt" if OS.linux?

        if !["librpm", "python", "librdkafka"].include?(self.name)
          append "CFLAGS", "-fvisibility=hidden -fvisibility-inlines-hidden"
          append "CXXFLAGS", "-fvisibility=hidden -fvisibility-inlines-hidden"
        end
      end

      if !["libgcrypt"].include?(self.name)
        # GCrypt includes a Pragma GCC to disable optimization.
        append "CFLAGS", "-Oz"
        append "CXXFLAGS", "-Oz"
      end

      append "LDFLAGS", "-fuse-ld=lld" if OS.linux?
      ENV["CPP"] = "#{default_prefix}/bin/clang-cpp" if OS.linux?
    end

    if !stage1_build
      # Set the search path for header files.
      prepend_path "CPATH", "#{default_prefix}/include"
      prepend_path "CPATH", "#{legacy_prefix}/include" if OS.linux?
      prepend_path "LD_RUN_PATH", "#{default_prefix}/lib"
    end

    # Adding this one line to help gcc too.
    # if !["fbthrift"].any?{ |word| self.name.include?(word) }
    prepend "LDFLAGS", "-L#{default_prefix}/lib"
    prepend "LDFLAGS", "-L#{legacy_prefix}/lib" if OS.linux?

    prepend_path "LIBRARY_PATH", "#{legacy_prefix}/lib" if OS.linux?
    append "LDFLAGS", "-Wl,-rpath,#{default_prefix}/lib"
    append "LDFLAGS", "-lrt -lpthread -ldl -lz" if OS.linux?
  end

  def setup_inject
    return if setup

    puts "Hello from osquery setup: #{name}"

    # Reset compile flags for safety, we want to control them explicitly.
    reset "CFLAGS"
    reset "CXXFLAGS"
    reset "CPPFLAGS"
    reset "LDFLAGS"
    reset "LD_LIBRARY_PATH"
    reset "LD_RUN_PATH"
    reset "CPATH"
    reset "LIBRARY_PATH"

    if !libc_build
      self.setup_runtimes
    end

    append "CFLAGS", "-fPIC -DNDEBUG -march=core2"
    append "CXXFLAGS", "-fPIC -DNDEBUG -march=core2"

    # macOS compatibility flags.
    if OS.mac?
      append "CFLAGS", "-mmacosx-version-min=10.11"
      append "CXXFLAGS", "-mmacosx-version-min=10.11"
      append "LDFLAGS", "-mmacosx-version-min=10.11"
      ENV["MACOSX_DEPLOYMENT_TARGET"] = "10.11"
      # We cannot include this for various reasons, e.g., curl provides _connectx.
      # append "LDFLAGS", "-Wl,-no_weak_imports" if OS.mac?

      # MacOS 10.12/Xcode 9 SDK new ABIs.
      %w[fmemopen futimens open_memstream utimensat].each do |s|
        ENV["ac_cv_func_#{s}"] = "no"
      end

      # MacOS 10.11/Xcode 8 SDK new ABIs.
      %w[basename_r clock_getres clock_gettime clock_settime dirname_r
         getentropy mkostemp mkostemps timingsafe_bcmp].each do |s|
       ENV["ac_cv_func_#{s}"] = "no"
      end

      ENV["ac_cv_search_clock_gettime"] = "no"
      ENV["ac_have_clock_syscall"] = "no"
    end

    prepend_path "PATH", "#{default_prefix}/bin" if OS.mac?
    prepend_path "PYTHONPATH", "#{default_prefix}/lib/python2.7/site-packages" if OS.mac?
    prepend_path "PKG_CONFIG_PATH", "#{default_prefix}/lib/pkgconfig"
    prepend_path "PKG_CONFIG_PATH", "#{legacy_prefix}/lib/pkgconfig" if OS.linux?
    prepend_path "ACLOCAL_PATH", "#{default_prefix}/share/aclocal"

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
    puts ":: PKG_CONFIG_PATH : " + ENV["PKG_CONFIG_PATH"].to_s
  end
end
