# Changelog

## [Unreleased]

- reject symlink ancestors while materializing parent directories for staged atomic file/directory writes, so atomic staging no longer follows ambient path redirects outside the intended root
