# frozen_string_literal: true

require "fileutils"
require "minitest/autorun"
require "open3"
require "pathname"
require "tmpdir"

REPO_ROOT = File.expand_path("../../..", __dir__)

CommandResult = Struct.new(:stdout, :stderr, :status) do
  def success?
    status.success?
  end
end

module ScriptTestSupport
  def run_command(*command, env: {}, chdir: REPO_ROOT)
    stdout, stderr, status = Open3.capture3(env, *command, chdir: chdir)
    CommandResult.new(stdout, stderr, status)
  end

  def ruby_script(*relative)
    File.join(REPO_ROOT, *relative)
  end

  def assert_file_has_line(path, expected_line)
    lines = File.readlines(path, chomp: true, encoding: "utf-8")
    assert_includes(lines, expected_line, "expected #{path} to contain line: #{expected_line}")
  end
end

class Minitest::Test
  include ScriptTestSupport
end
