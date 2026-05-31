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
      assert_complete_or_empty("server certificate material", paths[:server_runtime_dir], SERVER_RUNTIME_FILES)
      assert_complete_or_empty("client identity material", paths[:client_runtime_dir], CLIENT_RUNTIME_FILES)
      build_image(repo_root, IMAGE_TAG)
      prepare_server_certificate_material(example_dir, paths, IMAGE_TAG)
      prepare_client_identity_material(example_dir, paths, IMAGE_TAG)
      render_runtime_configuration(paths, example_dir)

      Core.success("Docker example is ready")
      Core.note("Generated state: #{generated_dir}")
      Core.note("Runtime material: generated/server/data and generated/client/data")
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
    CONTAINER_XDG_DATA_HOME = "/tmp/runewarp-data"
    SERVER_RUNTIME_FILES = [
      "server.crt",
      "server.key",
      "server-ca.crt"
    ].freeze
    CLIENT_RUNTIME_FILES = ["client.crt", "client.key", "client-identity.txt"].freeze

    def layout(example_dir)
      generated_dir = File.join(example_dir, "generated")
      server_service_dir = File.join(generated_dir, "server")
      client_service_dir = File.join(generated_dir, "client")
      caddy_service_dir = File.join(generated_dir, "caddy")

      {
        generated_dir: generated_dir,
        server_runtime_dir: File.join(server_service_dir, "data", "runewarp", "server", "cert"),
        server_config_path: File.join(server_service_dir, "config", "runewarp", "config.toml"),
        client_runtime_dir: File.join(client_service_dir, "data", "runewarp", "client", "identity"),
        client_trust_path: File.join(client_service_dir, "data", "runewarp", "client", "server-ca.crt"),
        client_config_path: File.join(client_service_dir, "config", "runewarp", "config.toml"),
        caddy_data_dir: File.join(caddy_service_dir, "data"),
        caddy_config_dir: File.join(caddy_service_dir, "config")
      }
    end

    def build_image(repo_root, image_tag)
      Core.section("Building local Runewarp image")
      Shell.run!(*DockerBuild.command(repo_root: repo_root, image_tag: image_tag))
    end

    def prepare_directories(paths)
      [
        paths[:server_runtime_dir],
        File.dirname(paths[:server_config_path]),
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

      Core.die("found incomplete #{label} in #{base_dir}; rerun ./scripts/docker-example prepare --reset to rebuild it cleanly")
    end

    def run_runewarp_in_temp_container(image_tag, *arguments)
      container_id = Shell.capture!(
        "docker",
        "create",
        "--env",
        "XDG_DATA_HOME=#{CONTAINER_XDG_DATA_HOME}",
        image_tag,
        *arguments
      ).strip

      begin
        Shell.run!("docker", "start", "-a", container_id)
        yield container_id
      ensure
        system("docker", "rm", "--force", container_id, out: File::NULL, err: File::NULL, exception: false)
      end
    end

    def install_container_files(container_id, container_root, destination_dir, relative_paths)
      relative_paths.each do |relative_path|
        destination_path = File.join(destination_dir, relative_path)
        FileUtils.mkdir_p(File.dirname(destination_path))
        Shell.run!("docker", "cp", "#{container_id}:#{container_root}/#{relative_path}", destination_path)
        File.chmod(0o444, destination_path)
      end
    end

    def prepare_server_certificate_material(example_dir, paths, image_tag)
      Core.section("Preparing server certificate material")
      if SERVER_RUNTIME_FILES.all? { |relative_path| File.file?(File.join(paths[:server_runtime_dir], relative_path)) }
        Core.note("Reusing existing server certificate material")
        return
      end

      Core.note("Generating certificate material for tunnel.example.test")
      run_runewarp_in_temp_container(image_tag, "server", "cert", "init", "--hostname", "tunnel.example.test") do |container_id|
        install_container_files(
          container_id,
          "#{CONTAINER_XDG_DATA_HOME}/runewarp/server/cert",
          paths[:server_runtime_dir],
          SERVER_RUNTIME_FILES
        )
      end
    end

    def prepare_client_identity_material(example_dir, paths, image_tag)
      Core.section("Preparing client identity material")
      if CLIENT_RUNTIME_FILES.all? { |relative_path| File.file?(File.join(paths[:client_runtime_dir], relative_path)) }
        Core.note("Reusing existing client identity material")
        return
      end

      Core.note("Generating client identity material")
      run_runewarp_in_temp_container(image_tag, "client", "identity", "init") do |container_id|
        install_container_files(
          container_id,
          "#{CONTAINER_XDG_DATA_HOME}/runewarp/client/identity",
          paths[:client_runtime_dir],
          CLIENT_RUNTIME_FILES
        )
      end
    end

    def render_runtime_configuration(paths, example_dir)
      Core.section("Rendering Docker example configuration")
      Core.install_readonly_copy(File.join(paths[:server_runtime_dir], "server-ca.crt"), paths[:client_trust_path])

      client_identity = File.read(File.join(paths[:client_runtime_dir], "client-identity.txt"), encoding: "utf-8").delete(" \n\r\t")
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
