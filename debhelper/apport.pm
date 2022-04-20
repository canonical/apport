#!/usr/bin/perl
# debhelper sequence file for apport

use warnings;
use strict;
use Debian::Debhelper::Dh_Lib;

insert_after("dh_bugfiles", "dh_apport");

1;
