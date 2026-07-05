# frozen_string_literal: true

require_relative "support/test_helper"
require_relative "../lib/runewarp"

class DockerExampleTest < Minitest::Test
  def test_readme_describes_prepare_without_a_manual_reproduction_script
    readme = File.read(File.join(REPO_ROOT, "examples", "docker", "README.md"), encoding: "utf-8")

    assert_includes(readme, "runewarp server cert init --hostname tunnel.example.test")
    assert_includes(readme, "runewarp client identity init")
    assert_includes(readme, "normal operator setup")
    refute_includes(readme, "docker run --rm")
    refute_includes(readme, "mkdir -p \\")
  end

  def test_entrypoint_shows_prepare_and_smoke_subcommands
    result = run_command(ruby_script("scripts", "docker-example"), "--help")

    refute(result.success?)
    assert_includes(result.stderr, "usage: docker-example <prepare|smoke> [--image-ref IMAGE_REF]")
  end

  def with_path(path)
    original_path = ENV["PATH"]
    ENV["PATH"] = "#{path}:#{original_path}"
    yield
  ensure
    ENV["PATH"] = original_path
  end

  def write_executable(path, content)
    File.write(path, content, encoding: "utf-8")
    File.chmod(0o755, path)
  end

  def write_example_fixture(example_dir)
    FileUtils.mkdir_p(File.join(example_dir, "server"))
    FileUtils.mkdir_p(File.join(example_dir, "client"))
    File.write(File.join(example_dir, "docker-compose.yml"), "services: {}\n", encoding: "utf-8")
    File.write(File.join(example_dir, "server", "config.toml.template"), "client_identity = \"__CLIENT_IDENTITY__\"\n", encoding: "utf-8")
    File.write(File.join(example_dir, "client", "config.toml.template"), "client = true\n", encoding: "utf-8")
  end

  def write_docker_stub(bin_dir, example_dir, commands_file: nil)
    write_executable(
      File.join(bin_dir, "docker"),
      <<~RUBY
        #!/usr/bin/env ruby
        require "fileutils"

        example_dir = ENV.fetch("TEST_EXAMPLE_DIR")
        commands_file = #{commands_file.inspect}
        args = ARGV.dup
        File.open(commands_file, "a", encoding: "utf-8") { |handle| handle.puts(args.join(" ")) } unless commands_file.nil?

        SERVER_FILES = {
          "/tmp/runewarp-data/runewarp/server/cert/server.crt" => "server cert\\n",
          "/tmp/runewarp-data/runewarp/server/cert/server.key" => "server key\\n",
          "/tmp/runewarp-data/runewarp/server/cert/server-ca.crt" => "server ca\\n"
        }.freeze

        CLIENT_FILES = {
          "/tmp/runewarp-data/runewarp/client/identity/client.crt" => "client cert\\n",
          "/tmp/runewarp-data/runewarp/client/identity/client.key" => "client key\\n",
          "/tmp/runewarp-data/runewarp/client/identity/client-identity.txt" => "client-identity\\n"
        }.freeze

        def container_state_path(example_dir)
          File.join(example_dir, "fake-containers")
        end

        def write_container_files(example_dir, container_id, files)
          base = File.join(container_state_path(example_dir), container_id)
          files.each do |path, content|
            full_path = File.join(base, path.sub(%r{\\A/}, ""))
            FileUtils.mkdir_p(File.dirname(full_path))
            File.write(full_path, content, encoding: "utf-8")
          end
        end

        def copy_from_container(example_dir, source, destination)
          container_id, container_path = source.split(":", 2)
          source_path = File.join(container_state_path(example_dir), container_id, container_path.sub(%r{\\A/}, ""))
          FileUtils.mkdir_p(File.dirname(destination))
          FileUtils.cp(source_path, destination)
        end

        case args[0]
        when "compose"
          command = args[1] == "version" ? "version" : args[3]
          case command
          when "version", "down", "up", "logs"
            exit 0
          when "exec"
            shell_command = args.last
            case shell_command
            when /\\Atest -f /
              exit 0
            when /\\Acat /
              $stdout.write("fake root ca\\n")
              exit 0
            end
          end
        when "build"
          exit 0
        when "buildx"
          exit 0
        when "create"
          container_id = "container-\#{args.last.gsub(/[^a-z-]/, "-")}"
          if args.include?("server") && args.include?("cert") && args.include?("init")
            write_container_files(example_dir, container_id, SERVER_FILES)
            $stdout.puts(container_id)
            exit 0
          end
          if args.include?("client") && args.include?("identity") && args.include?("init")
            write_container_files(example_dir, container_id, CLIENT_FILES)
            $stdout.puts(container_id)
            exit 0
          end
        when "start", "rm"
          exit 0
        when "cp"
          copy_from_container(example_dir, args[1], args[2])
          exit 0
        end

        abort("unexpected docker invocation: \#{args.inspect}")
      RUBY
    )
  end

  def write_curl_stub(bin_dir)
    write_executable(
      File.join(bin_dir, "curl"),
      <<~RUBY
        #!/usr/bin/env ruby
        url = ARGV.last
        body = case url
               when "https://app.example.test:8443/"
                 "app.example.test via runewarp\\n"
               when "https://api.example.test:8443/"
                 "api.example.test via runewarp\\n"
               else
                 abort("unexpected curl url: \#{url}")
               end
        $stdout.write(body)
      RUBY
    )
  end

  def test_smoke_accepts_trailing_newline_in_curl_body
    Dir.mktmpdir do |temp_dir|
      example_dir = File.join(temp_dir, "example")
      bin_dir = File.join(temp_dir, "bin")
      FileUtils.mkdir_p(bin_dir)
      write_example_fixture(example_dir)
      write_docker_stub(bin_dir, example_dir)
      write_curl_stub(bin_dir)

      with_path(bin_dir) do
        ENV["TEST_EXAMPLE_DIR"] = example_dir
        Runewarp::DockerExample.smoke(example_dir: example_dir, repo_root: REPO_ROOT)
      ensure
        ENV.delete("TEST_EXAMPLE_DIR")
      end
    end
  end

  def test_prepare_stages_runtime_material_without_source_data_directories
    Dir.mktmpdir do |temp_dir|
      example_dir = File.join(temp_dir, "example")
      bin_dir = File.join(temp_dir, "bin")
      FileUtils.mkdir_p(bin_dir)
      write_example_fixture(example_dir)
      write_docker_stub(bin_dir, example_dir)

      with_path(bin_dir) do
        ENV["TEST_EXAMPLE_DIR"] = example_dir
        Runewarp::DockerExample.prepare(example_dir: example_dir, repo_root: REPO_ROOT, reset_requested: false)
      ensure
        ENV.delete("TEST_EXAMPLE_DIR")
      end

      assert_path_exists(File.join(example_dir, "generated", "server", "data", "runewarp", "server", "cert", "server.crt"))
      assert_path_exists(File.join(example_dir, "generated", "client", "data", "runewarp", "client", "identity", "client.crt"))
      refute_path_exists(File.join(example_dir, "generated", "server", "source-data"))
      refute_path_exists(File.join(example_dir, "generated", "client", "source-data"))
    end
  end

  def test_prepare_uses_workflow_provided_build_cache_flags
    Dir.mktmpdir do |temp_dir|
      example_dir = File.join(temp_dir, "example")
      bin_dir = File.join(temp_dir, "bin")
      commands_file = File.join(temp_dir, "docker-commands.txt")
      FileUtils.mkdir_p(bin_dir)
      write_example_fixture(example_dir)
      write_docker_stub(bin_dir, example_dir, commands_file: commands_file)

      with_path(bin_dir) do
        ENV["TEST_EXAMPLE_DIR"] = example_dir
        ENV["RUNEWARP_DOCKER_BUILD_FLAGS"] = "--cache-from type=gha,scope=ci-docker --cache-to type=gha,scope=ci-docker,mode=max"
        Runewarp::DockerExample.prepare(example_dir: example_dir, repo_root: REPO_ROOT, reset_requested: false)
      ensure
        ENV.delete("RUNEWARP_DOCKER_BUILD_FLAGS")
        ENV.delete("TEST_EXAMPLE_DIR")
      end

      assert_includes(
        File.read(commands_file, encoding: "utf-8"),
        "buildx build --load --cache-from type=gha,scope=ci-docker --cache-to type=gha,scope=ci-docker,mode=max --build-arg RUNEWARP_BUILD_COMMIT="
      )
    end
  end

  def test_prepare_can_stage_a_published_image_without_building_local_image
    Dir.mktmpdir do |temp_dir|
      example_dir = File.join(temp_dir, "example")
      bin_dir = File.join(temp_dir, "bin")
      commands_file = File.join(temp_dir, "docker-commands.txt")
      FileUtils.mkdir_p(bin_dir)
      write_example_fixture(example_dir)
      write_docker_stub(bin_dir, example_dir, commands_file: commands_file)

      with_path(bin_dir) do
        ENV["TEST_EXAMPLE_DIR"] = example_dir
        Runewarp::DockerExample.prepare(
          example_dir: example_dir,
          repo_root: REPO_ROOT,
          reset_requested: false,
          image_ref: "docker.io/runewarp/runewarp:1234567890ab"
        )
      ensure
        ENV.delete("TEST_EXAMPLE_DIR")
      end

      commands = File.read(commands_file, encoding: "utf-8")
      refute_includes(commands, "buildx build")
      assert_includes(commands, "create --env XDG_DATA_HOME=/tmp/runewarp-data docker.io/runewarp/runewarp:1234567890ab server cert init --hostname tunnel.example.test\n")
      assert_includes(commands, "create --env XDG_DATA_HOME=/tmp/runewarp-data docker.io/runewarp/runewarp:1234567890ab client identity init\n")
      assert_equal("RUNEWARP_IMAGE=docker.io/runewarp/runewarp:1234567890ab\n", File.read(File.join(example_dir, ".env"), encoding: "utf-8"))
    end
  end
end
