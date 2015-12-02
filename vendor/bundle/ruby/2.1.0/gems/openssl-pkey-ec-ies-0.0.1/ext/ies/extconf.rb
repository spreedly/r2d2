require "mkmf"

Logging::message "=== OpenSSL ECIES extension configurator ===\n"

##
# Adds -DOSSL_DEBUG for compilation and some more targets when GCC is used
# To turn it on, use: --with-debug or --enable-debug
#
if with_config("debug") or enable_config("debug")
  $defs.push("-DOSSL_ECIES_DEBUG") unless $defs.include? "-DOSSL_ECIES_DEBUG"
end

result = pkg_config("openssl") && have_header("openssl/ssl.h")

unless result
  result = have_header("openssl/ssl.h")
  result &&= %w[crypto libeay32].any? {|lib| have_library(lib, "OpenSSL_add_all_digests")}
  result &&= %w[ssl ssleay32].any? {|lib| have_library(lib, "SSL_library_init")}
  unless result
    Logging::message "=== Checking for required stuff failed. ===\n"
    Logging::message "Makefile wasn't created. Fix the errors above.\n"
    exit 1
  end
end

unless have_header("openssl/conf_api.h")
  raise "OpenSSL 0.9.6 or later required."
end

create_header
create_makefile("openssl/pkey/ec/ies") {|conf|
  conf << "THREAD_MODEL = #{CONFIG["THREAD_MODEL"]}\n"
}
Logging::message "Done.\n"
