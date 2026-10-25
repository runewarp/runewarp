# frozen_string_literal: true

require "json"
require_relative "support/test_helper"
require_relative "../lib/runewarp"

class DistributionChecksTest < Minitest::Test
  def write_minimal_binary_crate(repo_root, version:)
    FileUtils.mkdir_p(File.join(repo_root, "src"))
    File.write(File.join(repo_root, "Cargo.toml"), <<~TOML, encoding: "utf-8")
      [package]
      name = "install-surface-fixture"
      version = "#{version}"
      edition = "2024"
      license = "Apache-2.0"
    TOML
    File.write(File.join(repo_root, "src", "main.rs"), <<~RUST, encoding: "utf-8")
      fn main() {
          if std::env::args().nth(1).as_deref() == Some("--version") {
              println!("install-surface-fixture {}", env!("CARGO_PKG_VERSION"));
              return;
          }

          println!("fixture");
      }
    RUST
    system("cargo", "generate-lockfile", chdir: repo_root, exception: true)
  end

  def write_executable(path, contents)
    File.write(path, contents, encoding: "utf-8")
    File.chmod(0o755, path)
  end

  def test_cargo_install_mode_installs_the_binary_and_checks_its_version
    Dir.mktmpdir do |repo_root|
      write_minimal_binary_crate(repo_root, version: "0.3.1")
      result = run_command(ruby_script("scripts", "check-distribution"), "cargo-install", "--repo-root", repo_root, "--bin-name", "install-surface-fixture", "--expected-version", "0.3.1")
      assert(result.success?, result.stderr)
    end
  end

  def write_recording_cargo(fake_bin_dir, commands_file, metadata_json: '{"packages":[]}')
    FileUtils.mkdir_p(fake_bin_dir)
    write_executable(
      File.join(fake_bin_dir, "cargo"),
      <<~RUBY
        #!/usr/bin/env ruby
        File.open(#{commands_file.inspect}, "a", encoding: "utf-8") do |handle|
          handle.puts("\#{ENV.fetch("CARGO_REGISTRIES_CRATES_IO_PROTOCOL", "")} \#{ARGV.join(" ")}")
        end
        puts(#{metadata_json.inspect}) if ARGV.first == "metadata"
      RUBY
    )
  end

  def with_path(path)
    original_path = ENV["PATH"]
    ENV["PATH"] = "#{path}:#{original_path}"
    yield
  ensure
    ENV["PATH"] = original_path
  end

  def test_package_readiness_runs_the_sparse_publish_dry_run_when_publishing_is_enabled
    Dir.mktmpdir do |repo_root|
      write_minimal_binary_crate(repo_root, version: "0.3.1")
      fake_bin_dir = File.join(repo_root, "fake-bin")
      commands_file = File.join(repo_root, "cargo-commands.txt")
      write_recording_cargo(fake_bin_dir, commands_file)

      with_path(fake_bin_dir) do
        Runewarp::DistributionChecks.validate_package_readiness(repo_root: repo_root, pause_reason: nil)
      end

      assert_equal(
        ["sparse publish --dry-run --allow-dirty --locked --manifest-path #{File.join(repo_root, 'Cargo.toml')}"],
        File.readlines(commands_file, chomp: true, encoding: "utf-8")
      )
    end
  end

  def test_package_readiness_skips_the_publish_dry_run_while_publishing_is_paused
    Dir.mktmpdir do |repo_root|
      write_minimal_binary_crate(repo_root, version: "0.3.1")
      fake_bin_dir = File.join(repo_root, "fake-bin")
      commands_file = File.join(repo_root, "cargo-commands.txt")
      write_recording_cargo(fake_bin_dir, commands_file)

      _stdout, stderr = capture_io do
        with_path(fake_bin_dir) do
          Runewarp::DistributionChecks.validate_package_readiness(repo_root: repo_root, pause_reason: "waiting for upstream")
        end
      end

      assert_equal(
        ["sparse metadata --format-version 1 --locked --manifest-path #{File.join(repo_root, 'Cargo.toml')}"],
        File.readlines(commands_file, chomp: true, encoding: "utf-8")
      )
      assert_includes(stderr, "skipped: cargo publish --dry-run; crates.io publishing is paused: waiting for upstream\n")
      assert_includes(stderr, "done: package readiness is valid\n")
    end
  end

  def test_package_readiness_rejects_unexpected_git_dependencies_while_publishing_is_paused
    Dir.mktmpdir do |repo_root|
      write_minimal_binary_crate(repo_root, version: "0.3.1")
      fake_bin_dir = File.join(repo_root, "fake-bin")
      commands_file = File.join(repo_root, "cargo-commands.txt")
      metadata_json = JSON.generate("packages" => [{ "name" => "quinn", "version" => "0.11.9", "source" => "git+https://github.com/quinn-rs/quinn#abc" }])
      write_recording_cargo(fake_bin_dir, commands_file, metadata_json: metadata_json)

      error = assert_raises(Runewarp::Error) do
        capture_io do
          with_path(fake_bin_dir) do
            Runewarp::DistributionChecks.validate_package_readiness(repo_root: repo_root, pause_reason: "waiting for upstream")
          end
        end
      end

      assert_equal(
        "error: unexpected git dependencies while crates.io publishing is paused; only h3, h3-quinn, h3-webtransport and h3-datagram from https://github.com/runewarp/h3 are allowed: quinn 0.11.9 (git+https://github.com/quinn-rs/quinn#abc)",
        error.message
      )
    end
  end

  def test_registry_install_mode_retries_until_the_registry_surface_is_available
    Dir.mktmpdir do |repo_root|
      write_minimal_binary_crate(repo_root, version: "0.3.1")
      fake_bin_dir = File.join(repo_root, "fake-bin")
      FileUtils.mkdir_p(fake_bin_dir)
      attempts_file = File.join(repo_root, "registry-install-attempts.txt")
      write_executable(
        File.join(fake_bin_dir, "cargo"),
        <<~RUBY
          #!/usr/bin/env ruby
          require "fileutils"
          attempts_file = #{attempts_file.inspect}
          count = File.exist?(attempts_file) ? File.read(attempts_file, encoding: "utf-8").to_i : 0
          count += 1
          File.write(attempts_file, count.to_s, encoding: "utf-8")
          abort("unsupported") unless ARGV.first == "install"
          if count < 3
            warn("not yet available")
            exit(1)
          end
          root = ARGV.each_cons(2).find { |a, _b| a == "--root" }&.last
          crate = ARGV.last
          FileUtils.mkdir_p(File.join(root, "bin"))
          File.write(File.join(root, "bin", crate), "#!/usr/bin/env ruby\\nputs \\"\#{crate} 0.3.1\\"\\n", encoding: "utf-8")
          File.chmod(0o755, File.join(root, "bin", crate))
        RUBY
      )

      result = run_command(ruby_script("scripts", "check-distribution"), "registry-install", "--crate-name", "install-surface-fixture", "--bin-name", "install-surface-fixture", "--expected-version", "0.3.1", "--retry-attempts", "3", "--retry-delay-seconds", "0", env: { "PATH" => "#{fake_bin_dir}:#{ENV.fetch('PATH')}" })
      assert(result.success?, result.stderr)
      assert_equal("3", File.read(attempts_file, encoding: "utf-8"))
    end
  end

  def test_registry_install_mode_rejects_zero_retry_attempts
    Dir.mktmpdir do |repo_root|
      write_minimal_binary_crate(repo_root, version: "0.3.1")
      result = run_command(ruby_script("scripts", "check-distribution"), "registry-install", "--crate-name", "install-surface-fixture", "--bin-name", "install-surface-fixture", "--expected-version", "0.3.1", "--retry-attempts", "0", "--retry-delay-seconds", "0")
      refute(result.success?)
      assert_includes(result.stderr, "--retry-attempts must be at least 1")
    end
  end

  def test_docker_registry_image_mode_pulls_and_runs_the_released_image
    Dir.mktmpdir do |repo_root|
      write_minimal_binary_crate(repo_root, version: "0.3.1")
      fake_bin_dir = File.join(repo_root, "fake-bin")
      FileUtils.mkdir_p(fake_bin_dir)
      commands_file = File.join(repo_root, "docker-commands.txt")
      write_executable(
        File.join(fake_bin_dir, "docker"),
        <<~RUBY
          #!/usr/bin/env ruby
          File.open(#{commands_file.inspect}, "a", encoding: "utf-8") { |handle| handle.puts(ARGV.join(" ")) }
          if ARGV.first == "pull"
            exit(0)
          elsif ARGV.first == "run"
            puts("Usage: runewarp")
            exit(0)
          end
          exit(1)
        RUBY
      )

      result = run_command(ruby_script("scripts", "check-distribution"), "docker-registry-image", "--image-ref", "docker.io/runewarp/runewarp:0.1.0", "--expected-text", "Usage: runewarp", "--probe-arg", "--help", env: { "PATH" => "#{fake_bin_dir}:#{ENV.fetch('PATH')}" })
      assert(result.success?, result.stderr)
      assert_equal("pull docker.io/runewarp/runewarp:0.1.0\nrun --rm docker.io/runewarp/runewarp:0.1.0 --help\n", File.read(commands_file, encoding: "utf-8"))
    end
  end

  def test_docker_registry_image_mode_targets_an_explicit_platform
    Dir.mktmpdir do |repo_root|
      write_minimal_binary_crate(repo_root, version: "0.3.1")
      fake_bin_dir = File.join(repo_root, "fake-bin")
      FileUtils.mkdir_p(fake_bin_dir)
      commands_file = File.join(repo_root, "docker-commands.txt")
      write_executable(
        File.join(fake_bin_dir, "docker"),
        <<~RUBY
          #!/usr/bin/env ruby
          File.open(#{commands_file.inspect}, "a", encoding: "utf-8") { |handle| handle.puts(ARGV.join(" ")) }
          if ARGV[0..2] == ["pull", "--platform", "linux/arm64"]
            exit(0)
          elsif ARGV[0..3] == ["run", "--rm", "--platform", "linux/arm64"]
            puts("runewarp 0.1.0")
            exit(0)
          end
          abort("unexpected docker invocation: \#{ARGV.inspect}")
        RUBY
      )

      result = run_command(
        ruby_script("scripts", "check-distribution"),
        "docker-registry-image",
        "--image-ref",
        "docker.io/runewarp/runewarp:0.1.0",
        "--platform",
        "linux/arm64",
        "--expected-version",
        "0.1.0",
        env: { "PATH" => "#{fake_bin_dir}:#{ENV.fetch('PATH')}" }
      )

      assert(result.success?, result.stderr)
      assert_equal(
        "pull --platform linux/arm64 docker.io/runewarp/runewarp:0.1.0\nrun --rm --platform linux/arm64 docker.io/runewarp/runewarp:0.1.0 --version\n",
        File.read(commands_file, encoding: "utf-8")
      )
    end
  end

  def test_docker_image_mode_uses_workflow_provided_build_cache_flags
    Dir.mktmpdir do |repo_root|
      write_minimal_binary_crate(repo_root, version: "0.3.1")
      fake_bin_dir = File.join(repo_root, "fake-bin")
      FileUtils.mkdir_p(fake_bin_dir)
      commands_file = File.join(repo_root, "docker-commands.txt")
      write_executable(
        File.join(fake_bin_dir, "docker"),
        <<~RUBY
          #!/usr/bin/env ruby
          File.open(#{commands_file.inspect}, "a", encoding: "utf-8") { |handle| handle.puts(ARGV.join(" ")) }
          if ARGV[0..3] == ["buildx", "build", "--load", "--cache-from"]
            exit(0)
          elsif ARGV.first == "run"
            puts("Usage: runewarp")
            exit(0)
          end
          abort("unexpected docker invocation: \#{ARGV.inspect}")
        RUBY
      )

      result = run_command(
        ruby_script("scripts", "check-distribution"),
        "docker-image",
        "--repo-root",
        repo_root,
        "--image-tag",
        "runewarp:test",
        "--expected-text",
        "Usage: runewarp",
        "--probe-arg",
        "--help",
        env: {
          "PATH" => "#{fake_bin_dir}:#{ENV.fetch('PATH')}",
          "RUNEWARP_DOCKER_BUILD_FLAGS" => "--cache-from type=gha,scope=ci --cache-to type=gha,scope=ci,mode=max"
        }
      )

      assert(result.success?, result.stderr)
      commands = File.read(commands_file, encoding: "utf-8")
      assert_includes(commands, "buildx build --load --cache-from type=gha,scope=ci --cache-to type=gha,scope=ci,mode=max")
      refute_includes(commands, "RUNEWARP_BUILD_COMMIT")
      assert_includes(commands, "--file #{File.join(repo_root, 'Dockerfile')} --tag runewarp:test #{repo_root}\n")
      assert_includes(commands, "run --rm runewarp:test --help\n")
    end
  end

  def test_docker_registry_image_mode_retries_until_the_image_is_available
    Dir.mktmpdir do |repo_root|
      write_minimal_binary_crate(repo_root, version: "0.3.1")
      fake_bin_dir = File.join(repo_root, "fake-bin")
      FileUtils.mkdir_p(fake_bin_dir)
      attempts_file = File.join(repo_root, "docker-pull-attempts.txt")
      write_executable(
        File.join(fake_bin_dir, "docker"),
        <<~RUBY
          #!/usr/bin/env ruby
          attempts_file = #{attempts_file.inspect}
          count = File.exist?(attempts_file) ? File.read(attempts_file, encoding: "utf-8").to_i : 0
          if ARGV.first == "pull"
            count += 1
            File.write(attempts_file, count.to_s, encoding: "utf-8")
            if count < 3
              warn("manifest unknown")
              exit(1)
            end
            exit(0)
          elsif ARGV.first == "run"
            puts("runewarp 0.1.0")
            exit(0)
          end
          exit(1)
        RUBY
      )

      result = run_command(ruby_script("scripts", "check-distribution"), "docker-registry-image", "--image-ref", "docker.io/runewarp/runewarp:0.1.0", "--expected-version", "0.1.0", "--retry-attempts", "3", "--retry-delay-seconds", "0", env: { "PATH" => "#{fake_bin_dir}:#{ENV.fetch('PATH')}" })
      assert(result.success?, result.stderr)
      assert_equal("3", File.read(attempts_file, encoding: "utf-8"))
    end
  end

  def test_docker_registry_image_mode_rejects_zero_retry_attempts
    Dir.mktmpdir do |repo_root|
      write_minimal_binary_crate(repo_root, version: "0.3.1")
      result = run_command(ruby_script("scripts", "check-distribution"), "docker-registry-image", "--image-ref", "docker.io/runewarp/runewarp:0.1.0", "--expected-version", "0.1.0", "--retry-attempts", "0", "--retry-delay-seconds", "0")
      refute(result.success?)
      assert_includes(result.stderr, "--retry-attempts must be at least 1")
    end
  end

  def test_docker_registry_tag_absent_mode_allows_a_new_version_tag
    Dir.mktmpdir do |repo_root|
      write_minimal_binary_crate(repo_root, version: "0.3.1")
      result = run_command(ruby_script("scripts", "check-distribution"), "docker-registry-tag-absent", "--image-ref", "docker.io/runewarp/runewarp:0.1.0", env: { "RUNEWARP_DOCKER_HUB_STATUS_OVERRIDE" => "404" })
      assert(result.success?, result.stderr)
    end
  end

  def test_docker_registry_tag_absent_mode_rejects_an_existing_version_tag
    Dir.mktmpdir do |repo_root|
      write_minimal_binary_crate(repo_root, version: "0.3.1")
      result = run_command(ruby_script("scripts", "check-distribution"), "docker-registry-tag-absent", "--image-ref", "docker.io/runewarp/runewarp:0.1.0", env: { "RUNEWARP_DOCKER_HUB_STATUS_OVERRIDE" => "200" })
      refute(result.success?)
      assert_includes(result.stderr, "docker registry tag already exists for docker.io/runewarp/runewarp:0.1.0")
    end
  end

  def test_package_readiness_mode_accepts_a_publishable_crate
    Dir.mktmpdir do |repo_root|
      write_minimal_binary_crate(repo_root, version: "0.3.1")
      result = run_command(ruby_script("scripts", "check-distribution"), "package-readiness", "--repo-root", repo_root)
      assert(result.success?, result.stderr)
    end
  end
end
