# frozen_string_literal: true

module Runewarp
  module DistributionChecks
    module_function

    def validate!(mode:, repo_root:, bin_name: nil, crate_name: nil, expected_version: nil, expected_text: nil, probe_arg: nil, image_tag: nil, image_ref: nil, retry_attempts: 10, retry_delay_seconds: 30)
      case mode
      when "cargo-install"
        validate_cargo_install(repo_root: repo_root, bin_name: bin_name, expected_version: expected_version, expected_text: expected_text, probe_arg: probe_arg)
      when "package-readiness"
        validate_package_readiness(repo_root: repo_root)
      when "registry-install"
        validate_registry_install(crate_name: crate_name, bin_name: bin_name, expected_version: expected_version, expected_text: expected_text, probe_arg: probe_arg, retry_attempts: retry_attempts, retry_delay_seconds: retry_delay_seconds)
      when "docker-image"
        validate_docker_image(repo_root: repo_root, expected_version: expected_version, expected_text: expected_text, probe_arg: probe_arg, image_tag: image_tag)
      when "docker-registry-image"
        validate_docker_registry_image(image_ref: image_ref, expected_version: expected_version, expected_text: expected_text, probe_arg: probe_arg, retry_attempts: retry_attempts, retry_delay_seconds: retry_delay_seconds)
      when "docker-registry-tag-absent"
        validate_docker_registry_tag_absent(image_ref: image_ref)
      else
        Core.usage_error("check_distribution <cargo-install|package-readiness|registry-install|docker-image|docker-registry-image|docker-registry-tag-absent> [--repo-root PATH] [--bin-name NAME] [--crate-name NAME] [--expected-version X.Y.Z] [--expected-text TEXT] [--probe-arg ARG] [--image-tag NAME] [--image-ref REF] [--retry-attempts COUNT] [--retry-delay-seconds SECONDS]")
      end
    end

    def validate_cargo_install(repo_root:, bin_name:, expected_version:, expected_text:, probe_arg:)
      Core.die("cargo-install mode requires --bin-name") if blank?(bin_name)
      validate_expected_output!(mode: "cargo-install", expected_version: expected_version, expected_text: expected_text)
      probe_arg ||= expected_version ? "--version" : "--help"

      Core.require_command("cargo")
      Core.with_temp_dir("runewarp-distribution-check-") do |install_root|
        Core.section("Installing crate from source")
        Core.note("Repository root: #{repo_root}")
        Core.note("Binary: #{bin_name}")

        Shell.run!("cargo", "install", "--locked", "--path", repo_root, "--root", install_root, out: File::NULL)

        Core.section("Checking installed binary")
        output = Shell.capture!(File.join(install_root, "bin", bin_name), probe_arg)
        validate_version_output!("installed binary", output, expected_version || expected_text)
        Core.success("cargo install path is valid")
      end
    end

    def validate_package_readiness(repo_root:)
      Core.require_command("cargo")

      Core.section("Checking package readiness")
      Core.note("Repository root: #{repo_root}")

      Shell.run!(
        "cargo",
        "publish",
        "--dry-run",
        "--allow-dirty",
        "--locked",
        "--manifest-path",
        File.join(repo_root, "Cargo.toml"),
        env: {
          "CARGO_REGISTRIES_CRATES_IO_PROTOCOL" => "sparse",
          "CARGO_HTTP_MULTIPLEXING" => "false",
          "CARGO_NET_RETRY" => "5"
        },
        out: File::NULL
      )

      Core.success("package readiness is valid")
    end

    def validate_registry_install(crate_name:, bin_name:, expected_version:, expected_text:, probe_arg:, retry_attempts:, retry_delay_seconds:)
      Core.die("registry-install mode requires --crate-name") if blank?(crate_name)
      Core.die("registry-install mode requires --bin-name") if blank?(bin_name)
      Core.die("registry-install mode requires --expected-version") if blank?(expected_version)
      validate_expected_output!(mode: "registry-install", expected_version: expected_version, expected_text: expected_text)
      probe_arg ||= expected_version ? "--version" : "--help"

      Core.require_command("cargo")
      Core.with_temp_dir("runewarp-distribution-check-") do |install_root|
        Core.section("Installing crate from crates.io")
        Core.note("Crate: #{crate_name}")
        Core.note("Binary: #{bin_name}")
        Core.note("Retry attempts: #{retry_attempts}")

        Core.retry_command(retry_attempts, retry_delay_seconds, "crate registry install", "crate registry install did not succeed after #{retry_attempts} attempts") do
          Shell.run!(
            "cargo",
            "install",
            "--locked",
            "--version",
            expected_version,
            "--root",
            install_root,
            crate_name,
            env: {
              "CARGO_REGISTRIES_CRATES_IO_PROTOCOL" => "sparse",
              "CARGO_HTTP_MULTIPLEXING" => "false",
              "CARGO_NET_RETRY" => "5"
            },
            out: File::NULL
          )
        end

        Core.section("Checking installed registry binary")
        output = Shell.capture!(File.join(install_root, "bin", bin_name), probe_arg)
        validate_version_output!("registry-installed binary", output, expected_version || expected_text)
        Core.success("crates.io install path is valid")
      end
    end

    def validate_docker_image(repo_root:, expected_version:, expected_text:, probe_arg:, image_tag:)
      validate_expected_output!(mode: "docker-image", expected_version: expected_version, expected_text: expected_text)
      Core.die("docker-image mode requires --image-tag") if blank?(image_tag)
      probe_arg ||= expected_version ? "--version" : "--help"

      Core.require_command("docker")
      Core.section("Building Docker image")
      Core.note("Repository root: #{repo_root}")
      Core.note("Image tag: #{image_tag}")
      Shell.run!("docker", "build", "--file", File.join(repo_root, "Dockerfile"), "--tag", image_tag, repo_root, out: File::NULL)

      Core.section("Checking Docker image startup")
      output = Shell.capture!("docker", "run", "--rm", image_tag, probe_arg)
      validate_version_output!("docker image", output, expected_version || expected_text)
      Core.success("docker image path is valid")
    end

    def validate_docker_registry_image(image_ref:, expected_version:, expected_text:, probe_arg:, retry_attempts:, retry_delay_seconds:)
      Core.die("docker-registry-image mode requires --image-ref") if blank?(image_ref)
      validate_expected_output!(mode: "docker-registry-image", expected_version: expected_version, expected_text: expected_text)
      probe_arg ||= expected_version ? "--version" : "--help"

      Core.require_command("docker")
      Core.section("Pulling Docker image")
      Core.note("Image ref: #{image_ref}")
      Core.note("Retry attempts: #{retry_attempts}")

      Core.retry_command(retry_attempts, retry_delay_seconds, "docker pull", "docker registry image did not become available after #{retry_attempts} attempts") do
        Shell.run!("docker", "pull", image_ref, out: File::NULL)
      end

      Core.section("Checking released Docker image startup")
      output = Shell.capture!("docker", "run", "--rm", image_ref, probe_arg)
      validate_version_output!("released docker image", output, expected_version || expected_text)
      Core.success("docker registry image path is valid")
    end

    def validate_docker_registry_tag_absent(image_ref:)
      Core.die("docker-registry-tag-absent mode requires --image-ref") if blank?(image_ref)

      Core.section("Checking Docker tag immutability")
      Core.note("Image ref: #{image_ref}")

      status = DockerHub.tag_status_from_image_ref(image_ref)
      case status
      when "404"
        Core.success("docker version tag is available for first publication")
      when "200"
        Core.die("docker registry tag already exists for #{image_ref}; cut a new patch version instead of republishing")
      else
        Core.die("unexpected Docker Hub tag lookup status for #{image_ref}: #{status}")
      end
    end

    def validate_expected_output!(mode:, expected_version:, expected_text:)
      return unless blank?(expected_version) && blank?(expected_text)

      Core.die("#{mode} mode requires --expected-version or --expected-text")
    end

    def validate_version_output!(command_label, output, expected_text)
      Core.die("#{command_label} output did not include expected text: #{expected_text}") unless output.include?(expected_text)
    end

    def blank?(value)
      value.nil? || value.empty?
    end
  end
end
