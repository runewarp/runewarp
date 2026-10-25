# frozen_string_literal: true

require "json"
require_relative "support/test_helper"

class BenchmarkVisitorCapacityTest < Minitest::Test
  def test_capture_metadata_omits_absolute_invocation_and_binary_paths
    Dir.mktmpdir do |directory|
      binary = File.join(directory, "private-bin")
      File.write(binary, "known binary bytes")
      python = <<~PYTHON
        import json, sys
        sys.path.insert(0, 'scripts')
        from lib.visitor_capacity_metadata import portable_invocation
        print(json.dumps(portable_invocation(
            [sys.argv[1] + '/private-script', '--output', sys.argv[1] + '/private-output', '--scenarios', 'burst', 'hold-two'],
            sys.argv[2])))
      PYTHON
      result = run_command("python3", "-B", "-c", python, directory, binary)
      assert(result.success?, result.stderr)
      metadata = JSON.parse(result.stdout)
      refute_includes(result.stdout, directory)
      assert_equal(["python3", "scripts/benchmark-visitor-capacity", "--output", "<output-directory>", "--scenarios", "burst", "hold-two"], metadata.fetch("command"))
      assert_equal("beef0b8105987de667468391df23b477e42156a12f90d33570c117f9b11f5acf", metadata.fetch("test_binary_sha256"))
    end
  end
end

class BenchmarkVisitorCapacityProvenanceTest < Minitest::Test
  def test_stale_binary_provenance_is_rejected_and_rust_changes_change_the_key
    Dir.mktmpdir do |directory|
      FileUtils.mkdir_p(File.join(directory, "src"))
      File.write(File.join(directory, "Cargo.toml"), "[package]\n")
      File.write(File.join(directory, "Cargo.lock"), "version = 4\n")
      File.write(File.join(directory, "src", "lib.rs"), "const BUDGET: usize = 8;\n")
      python = <<~PYTHON
        import json, sys
        from pathlib import Path
        sys.path.insert(0, 'scripts')
        from lib.visitor_capacity_metadata import rust_source_sha256, verify_binary_provenance
        root = Path(sys.argv[1])
        old = rust_source_sha256(root)
        (root / 'build-provenance.json').write_text(json.dumps({'rust_source_sha256': old}))
        verify_binary_provenance(root, old)
        (root / 'src/lib.rs').write_text('const BUDGET: usize = 256;\\n')
        current = rust_source_sha256(root)
        assert old != current
        try:
            verify_binary_provenance(root, current)
        except ValueError:
            print('stale binary rejected')
        else:
            raise AssertionError('stale binary was accepted')
      PYTHON
      result = run_command("python3", "-B", "-c", python, directory)
      assert(result.success?, result.stderr)
      assert_equal("stale binary rejected\n", result.stdout)
    end
  end
end
