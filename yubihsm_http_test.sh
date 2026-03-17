#!/bin/bash

cargo test --features yubihsm-http --no-default-features -- --ignored --test-threads=1 --nocapture
