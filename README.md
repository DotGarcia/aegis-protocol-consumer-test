# Aegis Protocol Consumer Test

Small external consumer used to validate `aegis-protocol` from crates.io.

It opens a local TCP connection, sends a hot-frame `CapturePayment` payload,
validates budget/replay/capability on the receiver and returns an Aegis ACK
frame.

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```
