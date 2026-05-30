#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "open3"

module Runewarp
  module DockerExample
    module_function

    def prepare(example_dir:, repo_root:, reset_requested:)
      generated_dir = File.join(example_dir, "generated")
      paths = layout(example_dir)

      Core.require_command("docker")
      reset_generated_state(example_dir, generated_dir) if reset_requested

      Core.section("Preparing Docker example state")
      prepare_directories(paths)
      assert_complete_or_empty("server certificate material", paths[:server_source_dir], SERVER_SOURCE_FILES)
      assert_complete_or_empty("client identity material", paths[:client_source_dir], CLIENT_SOURCE_FILES)

      build_image(repo_root, IMAGE_TAG)
      prepare_server_certificate_material(example_dir, paths, IMAGE_TAG)
      prepare_client_identity_material(example_dir, paths, IMAGE_TAG)
      render_runtime_configuration(paths, example_dir)

      Core.success("Docker example is ready")
      Core.note("Generated state: #{generated_dir}")
      Core.note("Source material: generated/server/source-data and generated/client/source-data")
    end

    def smoke(example_dir:, repo_root:)
      generated_dir = File.join(example_dir, "generated")
      compose_file = File.join(example_dir, "docker-compose.yml")
      caddy_root_ca = File.join(generated_dir, "caddy", "root.crt")
      caddy_container_root_ca = "/data/caddy/pki/authorities/local/root.crt"
      stack_started = false

      Core.require_command("docker")
      Core.require_command("curl")
      require_compose!(compose_file)

      begin
        reset_stack(compose_file)
        prepare(example_dir: example_dir, repo_root: repo_root, reset_requested: true)

        Core.section("Starting Docker example stack")
        Shell.run!("docker", "compose", "-f", compose_file, "up", "-d", out: File::NULL)
        stack_started = true

        wait_for_caddy_root_ca(compose_file, caddy_container_root_ca, caddy_root_ca, 30, 1)
        assert_hostname_response(compose_file, caddy_root_ca, "app.example.test", "app.example.test via runewarp")
        assert_hostname_response(compose_file, caddy_root_ca, "api.example.test", "api.example.test via runewarp")
      ensure
        if stack_started
          Core.section("Stopping Docker example stack")
          stop_stack(compose_file)
          Core.note("Docker example stack is down")
        end
      end

      Core.success("Smoke test passed")
      Core.note("Both public hostnames responded over TLS")
    end

    IMAGE_TAG = "runewarp/runewarp:local"
    SERVER_SOURCE_FILES = [
      "server.crt",
      "server.key",
      "server-ca.crt",
      "state/server-ca.key",
      "state/server-hostname.txt"
    ].freeze
    CLIENT_SOURCE_FILES = ["client.crt", "client.key", "client-identity.txt"].freeze

    def layout(example_dir)
      generated_dir = File.join(example_dir, "generated")
      server_service_dir = File.join(generated_dir, "server")
      client_service_dir = File.join(generated_dir, "client")
      caddy_service_dir = File.join(generated_dir, "caddy")

      {
        generated_dir: generated_dir,
        server_source_dir: File.join(server_service_dir, "source-data", "runewarp", "server", "cert"),
        server_state_dir: File.join(server_service_dir, "source-data", "runewarp", "server", "cert", "state"),
        server_runtime_dir: File.join(server_service_dir, "data", "runewarp", "server", "cert"),
        server_config_path: File.join(server_service_dir, "config", "runewarp", "config.toml"),
        client_source_dir: File.join(client_service_dir, "source-data", "runewarp", "client", "identity"),
        client_runtime_dir: File.join(client_service_dir, "data", "runewarp", "client", "identity"),
        client_trust_path: File.join(client_service_dir, "data", "runewarp", "client", "server-ca.crt"),
        client_config_path: File.join(client_service_dir, "config", "runewarp", "config.toml"),
        caddy_data_dir: File.join(caddy_service_dir, "data"),
        caddy_config_dir: File.join(caddy_service_dir, "config")
      }
    end

    def build_image(repo_root, image_tag)
      Core.section("Building local Runewarp image")
      Shell.run!("docker", "build", "--file", File.join(repo_root, "Dockerfile"), "--tag", image_tag, repo_root)
    end

    def prepare_directories(paths)
      [
        paths[:server_source_dir],
        paths[:server_state_dir],
        paths[:server_runtime_dir],
        File.dirname(paths[:server_config_path]),
        paths[:client_source_dir],
        paths[:client_runtime_dir],
        File.dirname(paths[:client_config_path]),
        File.dirname(paths[:client_trust_path]),
        paths[:caddy_data_dir],
        paths[:caddy_config_dir]
      ].each { |path| FileUtils.mkdir_p(path) }
    end

    def reset_generated_state(example_dir, generated_dir)
      Core.section("Resetting generated Docker example state")
      Core.note("Removing generated state")
      FileUtils.rm_rf(generated_dir)
      FileUtils.rm_f(File.join(example_dir, ".env"))
    end

    def assert_complete_or_empty(label, base_dir, relative_paths)
      return if relative_paths.all? { |relative_path| File.file?(File.join(base_dir, relative_path)) }
      return unless relative_paths.any? { |relative_path| File.exist?(File.join(base_dir, relative_path)) }

      Core.die("found incomplete #{label} in #{base_dir}; rerun prepare.rb --reset to rebuild it cleanly")
    end

    def run_runewarp_with_xdg_data_home(example_dir, image_tag, xdg_data_home, *arguments)
      Shell.run!(
        "docker",
        "run",
        "--rm",
        "--user",
        "#{Process.uid}:#{Process.gid}",
        "--volume",
        "#{example_dir}:/workspace",
        "--env",
        "XDG_DATA_HOME=#{xdg_data_home}",
        image_tag,
        *arguments
      )
    end

    def prepare_server_certificate_material(example_dir, paths, image_tag)
      Core.section("Preparing server certificate material")
      if SERVER_SOURCE_FILES.all? { |relative_path| File.file?(File.join(paths[:server_source_dir], relative_path)) }
        Core.note("Reusing existing server certificate material")
        return
      end

      Core.note("Generating certificate material for tunnel.example.test")
      run_runewarp_with_xdg_data_home(example_dir, image_tag, "/workspace/generated/server/source-data", "server", "cert", "init", "--hostname", "tunnel.example.test")
    end

    def prepare_client_identity_material(example_dir, paths, image_tag)
      Core.section("Preparing client identity material")
      if CLIENT_SOURCE_FILES.all? { |relative_path| File.file?(File.join(paths[:client_source_dir], relative_path)) }
        Core.note("Reusing existing client identity material")
        return
      end

      Core.note("Generating client identity material")
      run_runewarp_with_xdg_data_home(example_dir, image_tag, "/workspace/generated/client/source-data", "client", "identity", "init")
    end

    def render_runtime_configuration(paths, example_dir)
      Core.section("Rendering Docker example configuration")
      Core.install_readonly_copy(File.join(paths[:server_source_dir], "server.crt"), File.join(paths[:server_runtime_dir], "server.crt"))
      Core.install_readonly_copy(File.join(paths[:server_source_dir], "server.key"), File.join(paths[:server_runtime_dir], "server.key"))
      Core.install_readonly_copy(File.join(paths[:server_source_dir], "server-ca.crt"), File.join(paths[:server_runtime_dir], "server-ca.crt"))
      Core.install_readonly_copy(File.join(paths[:client_source_dir], "client.crt"), File.join(paths[:client_runtime_dir], "client.crt"))
      Core.install_readonly_copy(File.join(paths[:client_source_dir], "client.key"), File.join(paths[:client_runtime_dir], "client.key"))
      Core.install_readonly_copy(File.join(paths[:client_source_dir], "client-identity.txt"), File.join(paths[:client_runtime_dir], "client-identity.txt"))
      Core.install_readonly_copy(File.join(paths[:server_source_dir], "server-ca.crt"), paths[:client_trust_path])

      client_identity = File.read(File.join(paths[:client_source_dir], "client-identity.txt"), encoding: "utf-8").delete(" \n\r\t")
      server_template = File.read(File.join(example_dir, "server", "config.toml.template"), encoding: "utf-8")
      File.write(paths[:server_config_path], server_template.gsub("__CLIENT_IDENTITY__", client_identity), encoding: "utf-8")
      FileUtils.cp(File.join(example_dir, "client", "config.toml.template"), paths[:client_config_path])
    end

    def require_compose!(compose_file)
      return if Shell.successful?("docker", "compose", "version")

      Core.die("docker compose is required")
    end

    def stop_stack(compose_file)
      system("docker", "compose", "-f", compose_file, "down", "--volumes", "--remove-orphans", "--timeout", "1", out: File::NULL, err: File::NULL, exception: false)
    end

    def reset_stack(compose_file)
      Core.section("Resetting Docker example stack")
      stop_stack(compose_file)
    end

    def wait_for_caddy_root_ca(compose_file, container_path, host_path, attempts, delay_seconds)
      Core.section("Waiting for Caddy root CA")

      attempts.times do |index|
        if Shell.successful?("docker", "compose", "-f", compose_file, "exec", "-T", "caddy", "sh", "-c", "test -f '#{container_path}'")
          content = Shell.capture!("docker", "compose", "-f", compose_file, "exec", "-T", "caddy", "sh", "-c", "cat '#{container_path}'")
          File.write(host_path, content, encoding: "utf-8")
          Core.note("Copied root CA to #{host_path}")
          return
        end

        next if index + 1 >= attempts

        Core.note("Root CA not ready yet; retrying (#{index + 1}/#{attempts})")
        sleep(delay_seconds)
      end

      Core.warn("Timed out waiting for the Caddy root CA; dumping caddy logs")
      system("docker", "compose", "-f", compose_file, "logs", "--no-color", "caddy", exception: false)
      Core.die("timed out waiting for #{container_path} in the caddy container")
    end

    def assert_hostname_response(compose_file, caddy_root_ca, hostname, expected_body)
      Core.section("Verifying #{hostname}")

      30.times do |index|
        stdout, stderr, status = Open3.capture3(
          "curl",
          "--silent",
          "--show-error",
          "--fail",
          "--cacert",
          caddy_root_ca,
          "--resolve",
          "#{hostname}:8443:127.0.0.1",
          "https://#{hostname}:8443/"
        )

        if status.success?
          response = stdout.chomp
          if response == expected_body
            Core.note("Received the expected response")
            return
          end
          Core.die("expected #{hostname} to return '#{expected_body}', got '#{response}'")
        end

        next if index + 1 >= 30

        Core.note("Request failed; retrying (#{index + 1}/30): #{stderr.strip}")
        sleep(2)
      end

      Core.warn("Timed out waiting for #{hostname}; dumping docker compose logs")
      system("docker", "compose", "-f", compose_file, "logs", "--no-color", "caddy", "server", "client", exception: false)
      Core.die("timed out waiting for #{hostname} to respond over TLS")
    end
  end
end
