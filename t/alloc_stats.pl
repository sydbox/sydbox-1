#!/usr/bin/env perl
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

use strict;
use warnings;
use feature 'say';
use JSON 'decode_json';

my %alloc;
foreach my $line ( <STDIN> ) {
	chomp($line);
	my $data = decode_json ($line);
	next unless $data->{'event'};
	next unless $data->{'event'}->{'name'} eq 'alloc';
	$alloc{$data->{'func'}} += $data->{'size'};
}

my $argv = join(' ', @ARGV);
say "# Alloc stats for SydBox: $argv";
foreach my $func (sort keys %alloc) {
	next if ($func eq 'sum');
	say "$func: $alloc{$func}";
}
say "sum: $alloc{'sum'} bytes";
