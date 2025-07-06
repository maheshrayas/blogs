# syscall tracing

## PreRequistes

```bash
# Install cross
https://github.com/cross-rs/cross
```

## Build the code

```bash
cross build --target x86_64-unknown-linux-gnu
```

## Load and attach


```bash
sudo ./target/x86_64-unknown-linux-gnu/release/syscall-tracer
```
