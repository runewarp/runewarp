# frozen_string_literal: true

require "fileutils"

module Runewarp
  module WorkflowLint
    ACTIONLINT_IMAGE = "rhysd/actionlint:1.7.8"

    module_function

    def workflow_path?(candidate)
      candidate.match?(%r{\A\.github/workflows/[^/]+\.(yml|yaml)\z})
    end

    def normalize_workflow_path(repo_root, candidate)
      candidate.start_with?("#{repo_root}/") ? candidate.delete_prefix("#{repo_root}/") : candidate
    end

    def lint(repo_root:, staged_only:, requested_paths:)
      if staged_only
        raise UsageError, "usage: lint-workflows [--staged] [PATH ...]" unless requested_paths.empty?

        workflow_paths = staged_workflow_paths(repo_root)
        if workflow_paths.empty?
          Core.section("Linting workflows")
          Core.note("No staged workflow changes to lint")
          Core.success("workflow lint skipped")
          return
        end

        Core.with_temp_dir(".workflow-lint.", base: repo_root) do |lint_root|
          materialize_staged_workflows(repo_root, lint_root, workflow_paths)
          run_actionlint(lint_root, workflow_paths)
        end
        return
      end

      workflow_paths = requested_paths.map do |candidate|
        normalized = normalize_workflow_path(repo_root, candidate)
        Core.die("workflow path must be under .github/workflows: #{candidate}") unless workflow_path?(normalized)
        Core.die("workflow file not found: #{candidate}") unless File.file?(File.join(repo_root, normalized))

        normalized
      end

      run_actionlint(repo_root, workflow_paths)
    end

    def staged_workflow_paths(repo_root)
      output = Shell.capture!("git", "-C", repo_root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "--", ".github/workflows")
      output.lines(chomp: true).select { |candidate| workflow_path?(candidate) }
    end

    def materialize_staged_workflows(repo_root, lint_root, workflow_paths)
      workflow_paths.each do |candidate|
        destination = File.join(lint_root, candidate)
        FileUtils.mkdir_p(File.dirname(destination))
        content = Shell.capture!("git", "-C", repo_root, "show", ":#{candidate}")
        File.write(destination, content, encoding: "utf-8")
      end
    end

    def run_actionlint(lint_root, workflow_paths)
      Core.section("Linting workflows")
      Core.note("Lint root: #{lint_root}")
      Core.note("Workflow files: #{workflow_paths.empty? ? 'all' : workflow_paths.join(' ')}")

      if Core.command_available?("docker")
        Core.note("Runner: docker image #{ACTIONLINT_IMAGE}")
        command = ["docker", "run", "--rm", "-v", "#{lint_root}:/repo", "-w", "/repo", ACTIONLINT_IMAGE, "-color", *workflow_paths]
        Shell.run!(*command)
        return
      end

      Core.note("Runner: host actionlint + shellcheck")
      Core.require_command("actionlint")
      Core.require_command("shellcheck")

      command = ["actionlint", "-color", *workflow_paths]
      Shell.run!(*command, chdir: lint_root)
    end
  end
end
