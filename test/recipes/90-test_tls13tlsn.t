#! /usr/bin/env perl

use OpenSSL::Test::Utils;
use OpenSSL::Test qw/:DEFAULT srctop_file/;

setup("test_tls13tlsn");

plan skip_all => "tlsn needs TLS1.3 enabled"
    if disabled("tls1_3");

plan tests => 1;

ok(run(test(["tls13tlsntest", srctop_file("apps", "tlsn_cert.pem"), srctop_file("apps", "tlsn_key.pem"), srctop_file("apps", "tlsn_cert.pem")])), "Testing that tls13tlsn works correctly");
