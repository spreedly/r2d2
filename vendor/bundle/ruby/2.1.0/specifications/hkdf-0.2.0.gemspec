# -*- encoding: utf-8 -*-
# stub: hkdf 0.2.0 ruby lib

Gem::Specification.new do |s|
  s.name = "hkdf"
  s.version = "0.2.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib"]
  s.authors = ["John Downey"]
  s.date = "2012-09-23"
  s.description = "A ruby implementation of RFC5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF). The goal of HKDF is to take some source key material and generate suitable cryptographic keys from it."
  s.email = ["jdowney@gmail.com"]
  s.homepage = "http://github.com/jtdowney/hkdf"
  s.rubygems_version = "2.2.5"
  s.summary = "HMAC-based Key Derivation Function"

  s.installed_by_version = "2.2.5" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rspec>, [">= 0"])
    else
      s.add_dependency(%q<rspec>, [">= 0"])
    end
  else
    s.add_dependency(%q<rspec>, [">= 0"])
  end
end
