# frozen_string_literal: true

require_relative "support/test_helper"

class AuditDependenciesTest < Minitest::Test
  def run_audit_with_stub(installed_version:, binstall_available:)
    Dir.mktmpdir do |temp_dir|
      commands_file = File.join(temp_dir, "cargo-commands.txt")
      cargo_stub = File.join(temp_dir, "cargo")
      File.write(
        cargo_stub,
        <<~RUBY,
          #!/usr/bin/env ruby
          File.open(ENV.fetch("CARGO_COMMANDS_FILE"), "a", encoding: "utf-8") { |file| file.puts(ARGV.join(" ")) }
          if ARGV == ["audit", "--version"]
            puts ENV.fetch("CARGO_AUDIT_INSTALLED_VERSION")
          elsif ARGV == ["binstall", "--version"]
            exit(1)
          elsif ARGV == ["binstall", "-V"]
            exit(1) unless ENV.fetch("CARGO_BINSTALL_AVAILABLE") == "true"
            puts "cargo-binstall 1.21.0"
          end
        RUBY
        encoding: "utf-8"
      )
      File.chmod(0o755, cargo_stub)

      result = run_command(
        "ruby",
        ruby_script("scripts", "audit-dependencies"),
        env: {
          "CARGO_AUDIT_INSTALLED_VERSION" => installed_version,
          "CARGO_BINSTALL_AVAILABLE" => binstall_available.to_s,
          "CARGO_COMMANDS_FILE" => commands_file,
          "PATH" => "#{temp_dir}:#{ENV.fetch('PATH')}"
        }
      )
      yield result, commands_file
    end
  end

  def test_installs_the_pinned_cargo_audit_with_binstall
    run_audit_with_stub(installed_version: "cargo-audit 0.21.0", binstall_available: true) do |result, commands_file|
      assert(result.success?, result.stderr)
      assert_file_has_line(commands_file, "binstall -V")
      assert_file_has_line(commands_file, "binstall cargo-audit@0.22.2 --no-confirm --locked --force --disable-telemetry --only-signed")
      refute(File.readlines(commands_file, chomp: true).any? { |line| line.start_with?("install cargo-audit") })
    end
  end

  def test_falls_back_to_locked_source_install_without_binstall
    run_audit_with_stub(installed_version: "", binstall_available: false) do |result, commands_file|
      assert(result.success?, result.stderr)
      assert_file_has_line(commands_file, "install cargo-audit --version 0.22.2 --locked --force")
    end
  end

  def test_uses_the_installed_pinned_version_without_reinstalling
    run_audit_with_stub(installed_version: "cargo-audit-audit 0.22.2", binstall_available: false) do |result, commands_file|
      assert(result.success?, result.stderr)
      assert_equal(["audit --version", "audit"], File.readlines(commands_file, chomp: true))
    end
  end
end
