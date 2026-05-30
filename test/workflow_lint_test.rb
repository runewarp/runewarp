#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "support/test_helper"

class WorkflowLintTest < Minitest::Test
  def create_test_repo(temp_dir)
    FileUtils.mkdir_p(File.join(temp_dir, ".github", "workflows"))
    system("git", "-C", temp_dir, "init", "--quiet", exception: true)
    system("git", "-C", temp_dir, "config", "user.name", "Runewarp Test", exception: true)
    system("git", "-C", temp_dir, "config", "user.email", "runewarp-test@example.invalid", exception: true)
  end

  def test_no_arg_lints_all_workflows_without_empty_array_crash
    Dir.mktmpdir do |temp_dir|
      create_test_repo(temp_dir)
      File.write(
        File.join(temp_dir, ".github", "workflows", "ci.yml"),
        "name: CI\non: push\njobs:\n  workflow-lint:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
        encoding: "utf-8"
      )

      docker_stub = File.join(temp_dir, "docker")
      commands_file = File.join(temp_dir, "docker-commands.txt")
      File.write(
        docker_stub,
        "#!/usr/bin/env ruby\nFile.write(#{commands_file.inspect}, ARGV.join(' ') + \"\\n\")\n",
        encoding: "utf-8"
      )
      File.chmod(0o755, docker_stub)

      result = run_command(
        "ruby",
        ruby_script("scripts", "lint-workflows.rb"),
        env: {
          "PATH" => "#{temp_dir}:#{ENV.fetch('PATH')}",
          "RUNEWARP_REPO_ROOT" => temp_dir
        },
        chdir: temp_dir
      )

      assert(result.success?, result.stderr)
      assert_file_has_line(commands_file, "run --rm -v #{temp_dir}:/repo -w /repo rhysd/actionlint:1.7.8 -color")
      assert_includes(result.stderr, "Workflow files: all")
    end
  end

  def test_staged_mode_uses_index_content_from_repo_visible_temp_root
    Dir.mktmpdir do |temp_dir|
      create_test_repo(temp_dir)
      workflow_path = File.join(temp_dir, ".github", "workflows", "release.yml")
      File.write(workflow_path, "name: staged\non: push\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo staged\n", encoding: "utf-8")
      system("git", "-C", temp_dir, "add", ".github/workflows/release.yml", exception: true)
      File.write(workflow_path, "name: unstaged\non: push\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo unstaged\n", encoding: "utf-8")

      commands_file = File.join(temp_dir, "docker-commands.txt")
      mount_path_file = File.join(temp_dir, "mount-path.txt")
      linted_workflow_file = File.join(temp_dir, "linted-workflow.yml")
      docker_stub = File.join(temp_dir, "docker")
      File.write(
        docker_stub,
        <<~RUBY,
          #!/usr/bin/env ruby
          require "fileutils"
          File.open(#{commands_file.inspect}, "a", encoding: "utf-8") { |handle| handle.puts(ARGV.join(" ")) }
          volume_index = ARGV.index("-v")
          abort("missing -v") unless volume_index
          mount_root = ARGV[volume_index + 1].split(":").first
          File.write(#{mount_path_file.inspect}, mount_root, encoding: "utf-8")
          FileUtils.cp(File.join(mount_root, ".github", "workflows", "release.yml"), #{linted_workflow_file.inspect})
        RUBY
        encoding: "utf-8"
      )
      File.chmod(0o755, docker_stub)

      result = run_command(
        "ruby",
        ruby_script("scripts", "lint-workflows.rb"),
        "--staged",
        env: {
          "PATH" => "#{temp_dir}:#{ENV.fetch('PATH')}",
          "RUNEWARP_REPO_ROOT" => temp_dir
        },
        chdir: temp_dir
      )

      assert(result.success?, result.stderr)
      mount_root = File.read(mount_path_file, encoding: "utf-8")
      assert_file_has_line(commands_file, "run --rm -v #{mount_root}:/repo -w /repo rhysd/actionlint:1.7.8 -color .github/workflows/release.yml")
      assert_match(%r{\A#{Regexp.escape(temp_dir)}/\.workflow-lint\.}, mount_root)
      assert_file_has_line(linted_workflow_file, "name: staged")
      refute_includes(File.read(linted_workflow_file, encoding: "utf-8"), "name: unstaged")
    end
  end
end
