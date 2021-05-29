//
// pandora: Sydbox's Dump Inspector & Profile Writer
// src/lib.rs: Common utility functions
//
// Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub mod built_info {
    // The file has been placed there by the build script.
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}
