# newbp, for coding experiment
cargo build --release
cargo test --features c-headers -- generate_headers
go run load.go