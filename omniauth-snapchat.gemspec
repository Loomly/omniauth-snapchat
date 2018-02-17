
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "omniauth/snapchat/version"

Gem::Specification.new do |spec|
  spec.name          = "omniauth-snapchat"
  spec.version       = Omniauth::Snapchat::VERSION
  spec.authors       = ["Van Pham"]
  spec.email         = ["van@tenjin.com"]

  spec.summary       = %q{OnmiAuth Snapchat strategy}
  spec.homepage      = "https://github.com/Ordinance/omniauth-snapchat"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.16"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"

  spec.add_runtime_dependency 'omniauth', '~> 1.2'
  spec.add_runtime_dependency 'omniauth-oauth2', '~> 1.1'
end