#!/usr/bin/env perl
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

use strict;
use warnings;
use feature 'say';
unless (eval "use JSON 'decode_json'; 1") {
	# Exit silently, we don't want tests to break because of this.
	exit 0;
}

my %alloc;
$alloc{'sum'} = 0;
foreach my $line ( <STDIN> ) {
	chomp($line);
	my $data;
	eval {
		$data = decode_json($line);
	} or next;
	next unless $data->{'event'};
	next unless $data->{'event'}->{'name'} eq 'alloc';
	next unless $data->{'func'} eq 'sum';
	$alloc{$data->{'func'}} += $data->{'size'};
	$alloc{'sum'} += $data->{'size'};
}

my $argv = join(' ', @ARGV);
say "# Alloc stats for SydBox: $argv";
foreach my $func (sort keys %alloc) {
	next if ($func eq 'sum');
	say "$func: $alloc{$func}";
}
say "sum: $alloc{'sum'} bytes";
