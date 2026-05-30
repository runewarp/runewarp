#!/usr/bin/env ruby
# frozen_string_literal: true

require "open3"

module Runewarp
  module Shell
    module_function

    def capture!(*command, chdir: nil, env: {}, stdin_data: nil, allow_failure: false)
      options = {}
      options[:chdir] = chdir unless chdir.nil?
      options[:stdin_data] = stdin_data unless stdin_data.nil?
      stdout, stderr, status = Open3.capture3(env, *command, **options)
      return stdout if status.success? || allow_failure

      message = stderr.strip
      message = stdout.strip if message.empty?
      raise Error, "error: command failed: #{command.join(' ')}#{message.empty? ? '' : "\n#{message}"}"
    end

    def run!(*command, chdir: nil, env: {}, out: $stdout, err: $stderr)
      options = { out: out, err: err, exception: false }
      options[:chdir] = chdir unless chdir.nil?
      success = system(env, *command, **options)
      return if success

      raise Error, "error: command failed: #{command.join(' ')}"
    end

    def successful?(*command, chdir: nil, env: {})
      options = { out: File::NULL, err: File::NULL, exception: false }
      options[:chdir] = chdir unless chdir.nil?
      system(env, *command, **options)
    end
  end
end
