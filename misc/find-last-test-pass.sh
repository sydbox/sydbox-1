#!/bin/bash

src_test() {
    misc/conf.sh
    make -j
    pushd t
}

while ! good-or-bad-test-command ; do
       git checkout HEAD^
done
