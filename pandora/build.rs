//
// pandora: Sydb☮x's Dump Inspector & Profile Writer
// build.rs: Helper file for build-time information
//
// Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

fn main() {
    built::write_built_file().expect("Failed to acquire build-time information");
}
