#!/bin/sh
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test socket address matching'
. ./test-lib.sh

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS=
export SYDBOX_TEST_OPTIONS

test_expect_success 'invalid sockmatch' '
    test_expect_code 22 sockmatchtest &&
    test_expect_code 22 sockmatchtest inet:127.0.0.0/8@53 &&
    test_expect_code 22 sockmatchtest inet:127.0.0.0/8@53 unix:/run/nscd/socket
'

test_expect_success TODO 'unix: relative path is not supported' '
    test_expect_code 97 sockmatchtest unix:/foo unix:../bar
'

test_expect_success TODO 'unix: identical path matches' '
    sockmatchtest unix:/foo unix:/foo
'

test_expect_success TODO 'unix: non-identical path does not match' '
    test_expect_code 2 sockmatchtest unix:/foo unix:/bar
'

test_expect_success 'ipv4: identical ip without netmask matches' '
    sockmatchtest inet:1.2.3.4@53 inet:1.2.3.4@53
'

for mask in `seq 32 -1 0`; do
    test_expect_success "ipv4: identical ip with netmask /${mask} matches" "
        sockmatchtest inet:1.2.3.4/${mask}@53 inet:1.2.3.4@53
"
done

test_expect_success 'ipv4: identical ip without netmask matches with port in range' '
    sockmatchtest inet:1.2.3.4@50-55 inet:1.2.3.4@53 &&
    sockmatchtest inet:1.2.3.4@50-55 inet:1.2.3.4@50 &&
    sockmatchtest inet:1.2.3.4@50-55 inet:1.2.3.4@55
'

for mask in `seq 32 -1 0`; do
    test_expect_success "ipv4: identical ip with netmask /${mask} matches with port in range" "
        sockmatchtest inet:1.2.3.4/${mask}@50-55 inet:1.2.3.4@53 &&
        sockmatchtest inet:1.2.3.4/${mask}@50-55 inet:1.2.3.4@50 &&
        sockmatchtest inet:1.2.3.4/${mask}@50-55 inet:1.2.3.4@55
"
done

test_expect_success 'ipv4: identical ip without netmask does not match with port out of range' '
    test_expect_code 2 sockmatchtest inet:1.2.3.4@50-55 inet:1.2.3.4@49 &&
    test_expect_code 2 sockmatchtest inet:1.2.3.4@50-55 inet:1.2.3.4@56
'

for mask in `seq 32 -1 0`; do
    test_expect_success "ipv4: identical ip with netmask /${mask} does not match with port out of range" "
        test_expect_code 2 sockmatchtest inet:1.2.3.4/${mask}@50-55 inet:1.2.3.4@49 &&
        test_expect_code 2 sockmatchtest inet:1.2.3.4/${mask}@50-55 inet:1.2.3.4@56
"
done

test_expect_success 'ipv4: ip with different 4th part without netmask does not match' '
    test_expect_code 2 sockmatchtest inet:1.2.3.3@53 inet:1.2.3.4@53 &&
    test_expect_code 2 sockmatchtest inet:1.2.3.5@53 inet:1.2.3.4@53
'

for mask in `seq 32 -1 30`; do
    test_expect_success "ipv4: ip with different 4th part with netmask /${mask} does not match" "
        test_expect_code 2 sockmatchtest inet:1.2.3.3/${mask}@53 inet:1.2.3.4@53
"
done

for mask in `seq 29 -1 0`; do
    test_expect_success "ipv4: ip with different 4th part with netmask /${mask} matches" "
        sockmatchtest inet:1.2.3.3/${mask}@53 inet:1.2.3.4@53
"
done

for mask in `seq 31 -1 0`; do
    test_expect_success "ipv4: ip with different 4th part with netmask /${mask} matches" "
        sockmatchtest inet:1.2.3.5/${mask}@53 inet:1.2.3.4@53
"
done

test_expect_success 'ipv4: ip with different 3rd part without netmask does not match' '
    test_expect_code 2 sockmatchtest inet:1.2.1.4@53 inet:1.2.3.4@53 &&
    test_expect_code 2 sockmatchtest inet:1.2.2.4@53 inet:1.2.3.4@53
'

for mask in `seq 32 -1 24`; do
    test_expect_success "ipv4: ip with different 3rd part with netmask /${mask} does not match" "
        test_expect_code 2 sockmatchtest inet:1.2.1.4/${mask}@53 inet:1.2.3.4@53 &&
        test_expect_code 2 sockmatchtest inet:1.2.2.4/${mask}@53 inet:1.2.3.4@53
"
done

test_expect_success 'ipv4: ip with different 3rd part with netmask /23 does not match' '
    test_expect_code 2 sockmatchtest inet:1.2.1.4/23@53 inet:1.2.3.4@53
'

test_expect_success 'ipv4: ip with different 3rd part with netmask /23 matches' '
    sockmatchtest inet:1.2.2.4/23@53 inet:1.2.3.4@53
'

for mask in `seq 22 -1 0`; do
    test_expect_success "ipv4: ip with different 3rd part with netmask /${mask} matches" "
        sockmatchtest inet:1.2.1.4/${mask}@53 inet:1.2.3.4@53 &&
        sockmatchtest inet:1.2.2.4/${mask}@53 inet:1.2.3.4@53
"
done

test_expect_success 'ipv4: ip with different 2rd part without netmask does not match' '
    test_expect_code 2 sockmatchtest inet:1.1.3.4@53 inet:1.2.3.4@53 &&
    test_expect_code 2 sockmatchtest inet:1.3.3.4@53 inet:1.2.3.4@53
'

for mask in `seq 32 -1 16`; do
    test_expect_success "ipv4: ip with different 2rd part with netmask /${mask} does not match" "
        test_expect_code 2 sockmatchtest inet:1.1.3.4/${mask}@53 inet:1.2.3.4@53 &&
        test_expect_code 2 sockmatchtest inet:1.3.3.4/${mask}@53 inet:1.2.3.4@53
"
done

test_expect_success 'ipv4: ip with different 2rd part with netmask /15 does not match' '
    test_expect_code 2 sockmatchtest inet:1.1.3.4/15@53 inet:1.2.3.4@53
'

test_expect_success 'ipv4: ip with different 2rd part with netmask /15 matches' '
    sockmatchtest inet:1.3.3.4/15@53 inet:1.2.3.4@53
'

test_expect_success 'ipv4: ip with different 1st part without netmask does not match' '
    test_expect_code 2 sockmatchtest inet:0.2.3.4@53 inet:1.2.3.4@53 &&
    test_expect_code 2 sockmatchtest inet:3.2.3.4@53 inet:1.2.3.4@53
'

for mask in `seq 32 -1 8`; do
    test_expect_success "ipv4: ip with different 1st part with netmask /${mask} does not match" "
        test_expect_code 2 sockmatchtest inet:0.2.3.4/${mask}@53 inet:1.2.3.4@53 &&
        test_expect_code 2 sockmatchtest inet:3.2.3.4/${mask}@53 inet:1.2.3.4@53
"
done

test_expect_success 'ipv4: ip with different 1st part with netmask /7 matches' '
    sockmatchtest inet:0.2.3.4/7@53 inet:1.2.3.4@53
'

test_expect_success 'ipv4: ip with different 1st part with netmask /7 does not match' '
    test_expect_code 2 sockmatchtest inet:3.2.3.4/7@53 inet:1.2.3.4@53
'

#
### Corner cases
#
test_expect_success 'ipv4: ip with .253 suffix with netmask /31 does not match ip with .254 suffix' '
    test_expect_code 2 sockmatchtest inet:1.2.3.253/31@53 inet:1.2.3.254@53
'

test_expect_success 'ipv4: ip with .254 suffix with netmask /31 matches ip with .254 suffix' '
    sockmatchtest inet:1.2.3.254/31@53 inet:1.2.3.254@53
'

test_expect_success 'ipv4: ip with .255 suffix with netmask /31 matches ip with .254 suffix' '
    sockmatchtest inet:1.2.3.255/31@53 inet:1.2.3.254@53
'

test_expect_success 'ipv4: ip with .255 suffix with netmask /24 matches ip with .0 suffix' '
    sockmatchtest inet:1.2.3.255/24@53 inet:1.2.3.0@53
'

test_expect_success 'ipv4: ip with .255.255 suffix with netmask /23 matches ip with .254.0 suffix' '
    sockmatchtest inet:1.2.255.255/23@53 inet:1.2.254.0@53
'

test_expect_success 'ipv4: broadcast ip with netmask /1 matches ip with 128 prefix' '
    sockmatchtest inet:255.255.255.255/1@53 inet:128.0.0.0@53
'

test_expect_success 'ipv4: broadcast ip with netmask /1 does not match ip with 127 prefix' '
    test_expect_code 2 sockmatchtest inet:255.255.255.255/1@53 inet:127.0.0.0@53
'
###

#
### IPv6
#

test_expect_success HAVE_IPV6 'ipv6: identical ip with different last bit with netmask /127 matches' '
    sockmatchtest inet6:1234:5678::abcf/127@53 inet6:1234:5678::abce@53
'

test_expect_success HAVE_IPV6 'ipv6: identical ip with different last bit with netmask /127 does not match' '
    test_expect_code 2 sockmatchtest inet6:1234:5678::abcd/127@53 inet6:1234:5678::abce@53
'

test_expect_success HAVE_IPV6 'ipv6: identical prefix with netmask /15 matches' '
    sockmatchtest inet6:123e::ffff/15@53 inet6:123e::0@53
'
###

test_done
