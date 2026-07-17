# Quick Start

## Building
```
cargo build --release
```

## Running the daemon
```
# With a config file:
chronyd-rs -f /etc/chrony/chrony.conf

# In debug mode (foreground):
chronyd-rs -d -f /etc/chrony/chrony.conf

# As a simple lab daemon:
chronyd-rs --lab-daemon 3232
```

## Using the client
```
chronyc-rs tracking
chronyc-rs sources
chronyc-rs activity
```

## Checking syntax
```
chronyd-rs -p -f /etc/chrony/chrony.conf
```

## Testing
```
cargo test
cargo xtask check
```
