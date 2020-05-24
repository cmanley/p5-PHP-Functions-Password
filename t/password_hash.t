# This file must be saved in UTF-8 encoding!
use strict;
use warnings;
use Test::More;
use lib qw(../lib);

my @test_passwords = (
	'hello',
	'Test 123',
	'€U maffia',
);

my @methods = map { $_, "password_$_"; } qw(
	hash
	verify
);

my $php;
if (!($ENV{'HARNESS_ACTIVE'} || ($^O eq 'MSWin32'))) {	# experimental: that's why it's only executed when not in a test harness
	$php = `which php`;
	$php =~ s/^\s+|\s+$//g;
	if (-x $php) {
		my $phpversion = `php -v`;
		$phpversion =~ s/^PHP (\S+)\s.*/$1/s;
		if ($phpversion =~ /^(\d{1,3}\.\d{1,6})\b/) {
			if ($1 < 5.5) {
				undef($php);
			}
		}
		diag("Found PHP executable $php with version $phpversion: " . ($php ? 'OK' : 'TOO OLD') . "\n");
	}
	else {
		undef($php);
	}
}

plan tests => 1 + scalar(@methods) + ($php ? 4 : 3) * scalar(@test_passwords) * 3;

my $class = 'PHP::Functions::Password';
use_ok($class) || BAIL_OUT("Failed to use $class");

foreach my $method (@methods) {
	can_ok($class, $method);
	if ($method =~ /^password/) {
		$class->import($method);
	}
}

my %sig_to_algo = (
	'2y'       => $class->PASSWORD_BCRYPT,
	'argon2i'  => $class->PASSWORD_ARGON2I,
	'argon2id' => $class->PASSWORD_ARGON2ID,
);

foreach my $sig (sort keys %sig_to_algo) {
	my $algo_is_supported = scalar(grep { $_ eq $sig } $class->algos());
	SKIP: {
		$algo_is_supported || skip("Module(s) needed to support algorithm $sig not installed", 4 * scalar(@test_passwords));
		my $algo = $sig_to_algo{$sig};
		foreach my $password (@test_passwords) {
			my $crypted = $class->hash($password, 'algo' => $algo);
			ok(length($crypted) >= 60, "$class->hash(\"$password\", 'algo' => $algo) returns a crypted string");
			#diag("length $sig: " . length($crypted));
			if (1) {
				my $result = $class->verify($password, $crypted);
				ok($result, "Expect success from verify method using password \"$password\" and new crypted string \"$crypted\"");
				$result = password_verify($password, $crypted);
				ok($result, "Expect success from password_verify function using password \"$password\" and new crypted string \"$crypted\"");
			}
			if ($php) {
				my $phpcode = "var_export(password_verify('" . $password . "', '" . $crypted . "'));";
				my $h;
				open($h, '-|', $php, '-r', $phpcode) || die("Failed to execute $php: $!");
				my $line = <$h>;
				close($h);
				ok($line eq 'true', "Expect true from PHP's password_verify(\"$password\", \"$crypted\")");
			}
		}
	}
}


unless($ENV{'HARNESS_ACTIVE'}) {
	foreach my $password (@test_passwords) {
		#print password_hash($password, $class->PASSWORD_ARGON2ID, 'tag_length' => 16) . "\n";
		#print password_hash($password, $class->PASSWORD_BCRYPT) . "\n";
		#print password_hash($password, $class->PASSWORD_BCRYPT, 'salt' => Crypt::OpenSSL::Random::random_bytes(16)) . "\n";
		last;
	}
}
