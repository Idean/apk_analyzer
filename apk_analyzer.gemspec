# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'apk_analyzer/version'

Gem::Specification.new do |spec|
  spec.name          = 'apk_analyzer'
  spec.version       = ApkAnalyzer::VERSION
  spec.authors       = ['Guillem Mazarico', 'Emmanuel Konzi']
  spec.email         = %w(guillem.mazarico@backelite.com emmanuel.konzi@backelite.com)

  spec.summary       = %q{Android apk files analyzer}
  spec.description   = %q{The aim of this gem is to extract some data from android apk files. Analysis results
                          are printed in json. It can be used with CLI}
  spec.homepage      = "https://github.com/Backelite/apk_analyzer"
  spec.license       = "MIT"

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = "TODO: Set to 'http://mygemserver.com'"
  else
    raise "RubyGems 2.0 or newer is required to protect against " \
      "public gem pushes."
  end

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "bin"
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency 'apktools', '~>0.7.1'
  spec.add_runtime_dependency 'nokogiri', '~>1.5'

  spec.add_development_dependency "bundler", "~> 1.14"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "minitest", "~> 5.0"
end
