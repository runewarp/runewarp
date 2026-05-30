# frozen_string_literal: true

require_relative "support/test_helper"
require_relative "../lib/runewarp"

class DockerExampleTest < Minitest::Test
  def test_readme_documents_the_manual_prepare_commands
    readme = File.read(File.join(REPO_ROOT, "examples", "docker", "README.md"), encoding: "utf-8")

    assert_includes(readme, "runewarp server cert init --hostname tunnel.example.test")
    assert_includes(readme, "runewarp client identity init")
    assert_includes(readme, "docker run --rm")
  end

  def test_entrypoint_shows_prepare_and_smoke_subcommands
    result = run_command(ruby_script("scripts", "docker-example"), "--help")

    refute(result.success?)
    assert_includes(result.stderr, "usage: docker-example <prepare|smoke>")
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

  def write_docker_stub(bin_dir, example_dir)
    write_executable(
      File.join(bin_dir, "docker"),
      <<~RUBY
        #!/usr/bin/env ruby
        require "fileutils"

        example_dir = ENV.fetch("TEST_EXAMPLE_DIR")
        args = ARGV.dup

        def write_server_material(example_dir)
          base = File.join(example_dir, "generated", "server", "source-data", "runewarp", "server", "cert")
          FileUtils.mkdir_p(File.join(base, "state"))
          File.write(File.join(base, "server.crt"), "server cert\\n", encoding: "utf-8")
          File.write(File.join(base, "server.key"), "server key\\n", encoding: "utf-8")
          File.write(File.join(base, "server-ca.crt"), "server ca\\n", encoding: "utf-8")
          File.write(File.join(base, "state", "server-ca.key"), "server ca key\\n", encoding: "utf-8")
          File.write(File.join(base, "state", "server-hostname.txt"), "tunnel.example.test\\n", encoding: "utf-8")
        end

        def write_client_material(example_dir)
          base = File.join(example_dir, "generated", "client", "source-data", "runewarp", "client", "identity")
          FileUtils.mkdir_p(base)
          File.write(File.join(base, "client.crt"), "client cert\\n", encoding: "utf-8")
          File.write(File.join(base, "client.key"), "client key\\n", encoding: "utf-8")
          File.write(File.join(base, "client-identity.txt"), "client-identity\\n", encoding: "utf-8")
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
        when "run"
          if args.include?("server") && args.include?("cert") && args.include?("init")
            write_server_material(example_dir)
            exit 0
          end
          if args.include?("client") && args.include?("identity") && args.include?("init")
            write_client_material(example_dir)
            exit 0
          end
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
end
