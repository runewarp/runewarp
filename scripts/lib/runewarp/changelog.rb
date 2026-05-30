#!/usr/bin/env ruby
# frozen_string_literal: true

module Runewarp
  module Changelog
    ALLOWED_SUBSECTIONS = %w[Added Changed Deprecated Removed Fixed Security].freeze
    RELEASE_HEADING = /^## \[(?<version>[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?([+][0-9A-Za-z.-]+)?)\] - (?<date>\d{4}-\d{2}-\d{2})$/

    module_function

    def first_h2_heading(path)
      lines(path).find { |line| line.start_with?("## ") }&.sub(/^## /, "")
    end

    def normalize_heading(heading)
      return "Unreleased" if ["Unreleased", "[Unreleased]"].include?(heading)

      heading
    end

    def unreleased_heading?(path)
      lines(path).any? { |line| line.match?(/^## (\[Unreleased\]|Unreleased)$/) }
    end

    def validate_release_headings!(path)
      lines(path).each do |line|
        next unless line.start_with?("## ")
        next if ["## Unreleased", "## [Unreleased]"].include?(line)

        next if line.match?(RELEASE_HEADING)

        raise Error, "error: invalid changelog release heading: #{line}"
      end
    end

    def validate_subsection_headings!(path)
      in_section = false

      lines(path).each do |line|
        if line.start_with?("## ")
          in_section = true
          next
        end

        next unless line.start_with?("### ")

        heading = line.delete_prefix("### ")
        raise Error, "error: changelog subsection must appear under a changelog section: #{heading}" unless in_section
        raise Error, "error: invalid changelog subsection: #{heading}" unless ALLOWED_SUBSECTIONS.include?(heading)
      end
    end

    def validate_section_subsection_headings!(path, section_heading)
      in_section = false
      saw_section = false

      lines(path).each do |line|
        if line == section_heading
          in_section = true
          saw_section = true
          next
        end

        break if in_section && line.start_with?("## ")
        next unless in_section && line.start_with?("### ")

        heading = line.delete_prefix("### ")
        raise Error, "error: invalid changelog subsection: #{heading}" unless ALLOWED_SUBSECTIONS.include?(heading)
      end

      raise Error, "error: changelog release heading not found: #{section_heading}" unless saw_section
    end

    def find_release_heading(path, version)
      prefix = "## [#{version}] - "
      lines(path).find do |line|
        line.start_with?(prefix) && line.delete_prefix(prefix).match?(/^\d{4}-\d{2}-\d{2}$/)
      end
    end

    def section_has_list_item?(path, heading)
      in_section = false

      lines(path).each do |line|
        if line == heading
          in_section = true
          next
        end

        return false if in_section && line.start_with?("## ")
        return true if in_section && line.start_with?("- ")
      end

      false
    end

    def print_release_section(path, heading)
      in_section = false
      output = []

      lines(path).each do |line|
        if line == heading
          in_section = true
          next
        end

        break if in_section && line.start_with?("## ")
        next unless in_section

        output << (line.start_with?("### ") ? line.sub(/^### /, "## ") : line)
      end

      output.join("\n")
    end

    def lines(path)
      File.readlines(path, chomp: true, encoding: "utf-8")
    end
  end
end
