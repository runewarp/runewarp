# frozen_string_literal: true

require_relative "support/test_helper"

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

  def test_package_readiness_mode_uses_the_sparse_crates_io_protocol
    Dir.mktmpdir do |repo_root|
      write_minimal_binary_crate(repo_root, version: "0.3.1")
      fake_bin_dir = File.join(repo_root, "fake-bin")
      FileUtils.mkdir_p(fake_bin_dir)
      observed_protocol = File.join(repo_root, "observed-protocol.txt")
      write_executable(
        File.join(fake_bin_dir, "cargo"),
        <<~RUBY
          #!/usr/bin/env ruby
          File.write(#{observed_protocol.inspect}, "\#{ENV.fetch("CARGO_REGISTRIES_CRATES_IO_PROTOCOL", "")}\\n", encoding: "utf-8")
        RUBY
      )

      result = run_command(ruby_script("scripts", "check-distribution"), "package-readiness", "--repo-root", repo_root, env: { "PATH" => "#{fake_bin_dir}:#{ENV.fetch('PATH')}" })
      assert(result.success?, result.stderr)
      assert_equal("sparse\n", File.read(observed_protocol, encoding: "utf-8"))
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
