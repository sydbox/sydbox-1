#!/usr/bin/env perl
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

use strict;
use warnings;
use feature 'say';
use File::Basename;

my $dirname = dirname $0;
my $cookie;
if (-f "$dirname/tao.fortune") {
	$cookie="$dirname/tao.fortune";
} elsif (-f 'data/tao.fortune') {
	$cookie='data/tao.fortune';
} elsif (-f 'tao/tao.fortune') {
	$cookie='tao/tao.fortune';
} else {
	die 'Do not know where to find the fortune cookie file!';
}
open(TAO, '<', $cookie) or die $!;

my $fortune = "";
my @cookies;
while(<TAO>) {
	chomp($_);
	if ($_ ne '%') {
		$fortune .= "$_\n";
	} else {
		push @cookies, $fortune;
		$fortune = "";
	}
}
close TAO;

print "\x1b[92m$cookies[rand(@cookies)]\x1b[0m\n";
