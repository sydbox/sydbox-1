#!/usr/bin/env perl
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

use strict;
use warnings;
use feature 'say';
use Fcntl;

my $name = $ARGV[0];
die "Need /etc/passwd or /etc/group as first argument!" unless defined $name;
sysopen(my $passwd, $name, O_RDONLY|O_NOFOLLOW)
	or die "Can't open < '$name': $!";

my $uid;
my %user;
while (my $entry = <$passwd>) {
	chomp($entry);
	my @items = split(':', $entry);
	$uid = $items[2];
	$user{$uid} = $entry;
}
close($passwd);

foreach $uid (sort {$a <=> $b} (keys %user)) {
	say "$uid\t$user{$uid}";
}
