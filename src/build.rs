//
// SydB☮x: SydB☮x' Rust API
// build.rs: Helper file for build-time information
//
// Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

extern crate cbindgen;

fn main() {
    built::write_built_file().expect("Failed to acquire build-time information");

    cbindgen::generate(".")
        .expect("Unable to generate C bindings.")
        .write_to_file("sydbox_rs.h");
}
