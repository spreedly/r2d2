$LOAD_PATH.push File.expand_path("../lib", __FILE__)
require 'r2d2/version'

Gem::Specification.new do |s|
  s.name              = "r2d2"
  s.version           = R2D2::VERSION
  s.platform          = Gem::Platform::RUBY
  s.authors           = ["Miki Rezentes"]
  s.email             = ["miki@spreedly.com"]
  s.homepage          = "https://github.com/spreedly/r2d2"
  s.summary           = "Android Pay payment token decryption library"
  s.description       = "Given an (encrypted) Android Pay token, verify and decrypt it"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.required_ruby_version = ">= 1.8.7"

  s.add_runtime_dependency 'hkdf'
end
