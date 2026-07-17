# Semantic Versioning Policy

chrony-rs follows [Semantic Versioning 2.0.0](https://semver.org/).

## Version 0.x (development)

During the 0.x development phase:
- **Minor version** increments indicate new features, behavioral changes, and
  any changes to the public API of library crates
- **Patch version** increments indicate bug fixes and documentation changes
  that do not affect behavior

## Public API

The public API of `chrony-rs-core` includes:
- All `pub` items in the crate root module
- The `config::model` and `config::accessors` modules
- The `ntp::*`, `reference`, `local`, `sources`, `sourcestats` modules
- The `cmdmon`, `client`, `report` modules

Internal modules (containing `_` in their path or not listed above)
may change without notice.

## Breaking changes include:
- Adding required fields to public structs
- Changing enum variants or adding new variants to enums without `#[non_exhaustive]`
- Removing or changing public function signatures
- Changing default values that alter runtime behavior
