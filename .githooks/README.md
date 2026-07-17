# Git hooks for chrony-rs

Install: `git config core.hooksPath .githooks`

## pre-commit
Runs `cargo xtask check` to verify generated docs are fresh and pinned facts are accurate.
Fails the commit if the check fails.
