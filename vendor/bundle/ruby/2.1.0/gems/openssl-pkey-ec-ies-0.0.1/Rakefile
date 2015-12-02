require 'bundler/gem_tasks'
require 'rake/extensiontask'
require 'rake/testtask'

Rake::ExtensionTask.new 'ies' do |ext|
  ext.lib_dir = 'lib/openssl/pkey/ec'
end

Rake::TestTask.new do |t|
  t.libs << 'test'
  t.test_files = FileList['test/test*.rb']
  t.verbose = true
end

Rake::Task[:test].prerequisites << :compile
