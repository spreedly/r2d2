$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
require "r2d2"

require "minitest/autorun"

begin
  require "pry-byebug"
rescue LoadError
  # Ignore, byebug is not installed for older ruby versions
end

