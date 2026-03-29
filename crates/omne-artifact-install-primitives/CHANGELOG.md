# Changelog

## [Unreleased]

- clarify aggregated candidate failures so install-phase errors no longer report themselves as pure download failures
- serialize archive tree installs per destination with an advisory lock so concurrent installers cannot race staged directory replacement
