# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name          = 'openssl-pkey-ec-ies'
  spec.version       = '0.0.1'
  spec.authors       = ['webpay', 'tomykaira']
  spec.email         = ['administrators@webpay.jp']
  spec.summary       = %q{ECIES implementation}
  spec.description   = %q{IES implementation following ECIES-KEM specification in ISO 18033-2}
  spec.homepage      = ''
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']
  spec.extensions    = %w[ext/ies/extconf.rb]

  spec.add_development_dependency 'bundler', '~> 1.6'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rake-compiler', '~> 0.9.3'
end
