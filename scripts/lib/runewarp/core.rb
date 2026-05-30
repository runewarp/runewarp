# frozen_string_literal: true

require "fileutils"
require "tmpdir"

module Runewarp
  class Error < StandardError; end
  class UsageError < Error; end

  module Core
    module_function

    def section(message)
      $stderr.print("\n") if @section_started
      @section_started = true
      $stderr.puts("==> #{message}")
    end

    def note(message)
      $stderr.puts("  - #{message}")
    end

    def success(message)
      $stderr.puts("done: #{message}")
    end

    def warn(message)
      $stderr.puts("warning: #{message}")
    end

    def die(message)
      raise Error, "error: #{message}"
    end

    def usage_error(message)
      raise UsageError, "usage: #{message}"
    end

    def require_command(command)
      return if command_available?(command)

      die("#{command} is required")
    end

    def command_available?(command)
      ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).any? do |entry|
        File.executable?(File.join(entry, command))
      end
    end

    def runewarp_version(repo_root)
      cargo_toml = File.read(File.join(repo_root, "Cargo.toml"))
      match = cargo_toml.match(/^\s*version = "([^"]+)"/)
      match&.captures&.first
    end

    def runewarp_git_commit(repo_root)
      commit = ENV["RUNEWARP_GIT_COMMIT"]
      return commit unless commit.nil? || commit.empty?

      Shell.capture!("git", "-C", repo_root, "rev-parse", "--short=12", "HEAD").strip
    end

    def retry_command(retry_attempts, retry_delay_seconds, retry_label, failure_message)
      validate_retry_options!(retry_attempts, retry_delay_seconds)

      attempt = 1
      while attempt <= retry_attempts
        begin
          return yield
        rescue Error
          die(failure_message) if attempt == retry_attempts

          warn("#{retry_label} attempt #{attempt} failed; retrying after #{retry_delay_seconds}s")
          sleep(retry_delay_seconds)
          attempt += 1
        end
      end
    end

    def validate_retry_options!(retry_attempts, retry_delay_seconds)
      unless retry_attempts.is_a?(Integer) && retry_attempts >= 0
        die("--retry-attempts must be a non-negative integer")
      end
      unless retry_delay_seconds.is_a?(Integer) && retry_delay_seconds >= 0
        die("--retry-delay-seconds must be a non-negative integer")
      end
      die("--retry-attempts must be at least 1") if retry_attempts < 1
    end

    def with_temp_dir(prefix, base: nil)
      if base
        Dir.mktmpdir(prefix, base) do |path|
          yield path
        end
      else
        Dir.mktmpdir(prefix) do |path|
          yield path
        end
      end
    end

    def write_github_output(path, key, value)
      return if path.nil? || path.empty?

      File.open(path, "a", encoding: "utf-8") do |handle|
        handle.write("#{key}=#{value}\n")
      end
    end

    def write_github_multiline_output(path, key, value)
      return if path.nil? || path.empty?

      File.open(path, "a", encoding: "utf-8") do |handle|
        handle.write("#{key}<<EOF\n")
        handle.write(value)
        handle.write("\n") unless value.end_with?("\n")
        handle.write("EOF\n")
      end
    end

    def install_readonly_copy(source_path, destination_path)
      FileUtils.mkdir_p(File.dirname(destination_path))
      FileUtils.cp(source_path, destination_path)
      File.chmod(0o444, destination_path)
    end

    def run_cli
      yield
    rescue UsageError, Error => error
      $stderr.puts(error.message)
      exit(1)
    end
  end
end
