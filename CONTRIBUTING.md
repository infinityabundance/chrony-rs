# Contributing to chrony-rs

## How to contribute
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `cargo xtask check` to verify freshness
5. Run `cargo test` to verify correctness
6. Submit a pull request

## Code style
- Follow Rust standard formatting (use `cargo fmt`)
- All public items must have doc comments
- Safety-critical code should be tested with oracle differential tests
- Use `// SAFETY:` comments for all unsafe blocks
