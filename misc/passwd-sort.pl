#!/usr/bin/env perl
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

use strict;
use warnings;
use feature 'say';
use Fcntl;

my $name = $ARGV[0];
die "Need /etc/passwd or /etc/group as first argument!" unless defined $name;

my $limit = $ARGV[1];
$limit = 0 unless defined $limit;

sysopen(my $passwd, $name, O_RDONLY|O_NOFOLLOW)
	or die "Can't open < '$name': $!";

my $uid;
my %user;
while (my $entry = <$passwd>) {
	chomp($entry);
	my @items = split(':', $entry);
	$uid = $items[2];
	my $value = "$items[0]:$items[1]:$items[2]";
	$value .= ":$items[3]" if defined $items[3];
	$value .= ":$items[4]" if defined $items[4];
	$user{$uid} = $value;
}
close($passwd);

foreach $uid (sort {$a <=> $b} (keys %user)) {
	#say "$uid\t$user{$uid}";
	say "\t * $uid        $user{$uid}";
	last if ($limit > 0 && $uid >= $limit);
}
