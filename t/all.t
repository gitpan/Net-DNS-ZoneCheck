# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..1255\n"; }
END {print "not ok 1\n" unless $loaded;}
use Net::DNS;
use Net::DNS::ZoneCheck;
my $test = 1;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# we don't use advance Test:: modules, invent some little helpers
sub assert
{
	my ($exp,$descr,$extra) = @_;
	$test++;
	if ($exp) {
		print "ok $test # $descr\n";
	} else {
		if ($extra) {
			$extra =~ s/\n.*$//s;
			print "not ok $test # $descr, got `$extra'\n";
		} else {
			print "not ok $test # $descr\n";
		}
	}
}

sub eval_match
{
	my ($match, @rest) = @_;
	eval { Net::DNS::ZoneCheck::check(@rest); };
	assert(scalar($@ && $@ =~ /$match\n/), "expect `$match'", $@);
}

my $error;
sub test_error_handler {
	my %p = @_;
	$error = $p{error};
}

sub h_match
{
	my ($match, @rest) = @_;
	$error = "";
	Net::DNS::ZoneCheck::check(@rest, on_error => \&test_error_handler);
	if ($error eq $match || length($match) && $error =~ /^$match/) {
		assert(1, "expect `$match'", $error);
	} else {
		assert(0, "expect `$match'", $error);
	}
	$error = "";
}

# prepare test data
my $rr;
my (@check, @check_a, @check_r, @check_m, @check_all);
my $soa = new Net::DNS::RR "test.com. 30 IN SOA dns1.test.com. hostmaster.test.com. (1 2 3 4 5)";

my $acme_ns = new Net::DNS::RR "acme.com. 3600 IN NS dns1.acme.com.";
my $main_ns = new Net::DNS::RR "test.com. 3600 IN NS ns1.yahoo.com.";
my $main_ns2 = new Net::DNS::RR "test.com. 3600 IN NS ns2.yahoo.com.";
my $bad_net_ns = new Net::DNS::RR "test.com. 3600 IN NS tobez.org.";
my $sub_ns = new Net::DNS::RR "sub.test.com. 3600 IN NS ns1.yahoo.com.";
my $sub_ns2 = new Net::DNS::RR "sub.test.com. 3600 IN NS ns2.yahoo.com.";
my $sub_ns_del = new Net::DNS::RR "sub.test.com. 3600 IN NS sub.test.com.";
my $sub_sub_ns = new Net::DNS::RR "sub.sub.test.com. 3600 IN NS ns1.yahoo.com.";
my $ip_ns = new Net::DNS::RR "test.com. 3600 IN NS 1.2.3.4";
my $self_ns = new Net::DNS::RR "test.com. 3600 IN NS ns1.test.com.";
my $sub_self_ns = new Net::DNS::RR "sub.test.com. 3600 IN NS sub.test.com.";

my $rr_a = new Net::DNS::RR "test.com. 3600 IN A 1.2.3.4";
my $rr_a_ttl = new Net::DNS::RR "test.com. 3800 IN A 1.2.3.4";
my $rr_a2 = new Net::DNS::RR "test.com. 3600 IN A 4.3.2.1";
my $rr_a_out = new Net::DNS::RR "acme.com. 3600 IN A 4.3.2.1";
my $rr_a_ins = new Net::DNS::RR "sub.sub.test.com. 3600 IN A 4.3.2.1";
my $rr_a_sub = new Net::DNS::RR "sub.test.com. 3600 IN A 4.3.2.1";

my $rr_txt = new Net::DNS::RR "test.com. 3600 IN TXT \"Hello world\"";
my $rr_txt_ttl = new Net::DNS::RR "test.com. 520 IN TXT \"Hello world\"";
my $rr_txt2 = new Net::DNS::RR "test.com. 3600 IN TXT \"Hello world moo\"";
my $rr_txt_out = new Net::DNS::RR "acme.com. 3600 IN TXT \"Hello world\"";
my $rr_txt_ins = new Net::DNS::RR "sub.sub.test.com. 3600 IN TXT \"Hello world\"";
my $rr_txt_sub = new Net::DNS::RR "sub.test.com. 3600 IN TXT \"Hello world\"";

my $cname = new Net::DNS::RR "cname.test.com. 3600 IN CNAME sub.test.com.";
my $cname2 = new Net::DNS::RR "cname.test.com. 3600 IN CNAME xxx.test.com.";
my $cname_other = new Net::DNS::RR "test.com. 3600 IN CNAME sub.test.com.";
my $cname_other2 = new Net::DNS::RR "sub.test.com. 3600 IN CNAME xxx.test.com.";
my $cname_sub = new Net::DNS::RR "sub.test.com. 3600 IN CNAME test.com.";
my $cname_ip = new Net::DNS::RR "cname.test.com. 3600 IN CNAME 1.2.3.4";

my $mx_ip = new Net::DNS::RR "test.com. 3600 IN MX 10 1.2.3.4";
my $mx_cname = new Net::DNS::RR "test.com. 3600 IN MX 10 cname.test.com.";
my $mx_main = new Net::DNS::RR "test.com. 3600 IN MX 10 test.com.";

my $soa_ptr = new Net::DNS::RR "3.2.1.in-addr.arpa. 30 IN SOA dns1.test.com. hostmaster.test.com. (1 2 3 4 5)";
my $main_ns_ptr = new Net::DNS::RR "3.2.1.in-addr.arpa. 3600 IN NS ns1.yahoo.com.";
my $main_ns2_ptr = new Net::DNS::RR "3.2.1.in-addr.arpa. 3600 IN NS ns2.yahoo.com.";
my $ptr_ok = new Net::DNS::RR "42.3.2.1.in-addr.arpa. 3600 IN PTR something.test.com.";
my $ptr_inaddr = new Net::DNS::RR "42.3.2.1.in-addr.arpa. 3600 IN PTR 45.3.2.1.in-addr.arpa.";
my $ptr_ip6arpa = new Net::DNS::RR "42.3.2.1.in-addr.arpa. 3600 IN PTR 45.3.2.1.ip6.arpa.";
my $ptr_ip6int = new Net::DNS::RR "42.3.2.1.in-addr.arpa. 3600 IN PTR 45.3.2.1.ip6.int.";

# test error handling functionality of check()
eval_match("records parameter absent or bad");
eval_match("bad parameters", 1);
eval_match("records parameter absent or bad", records => 42);
eval_match("zone parameter required", records => []);
h_match("zone parameter required", records => []);
h_match("something which is not an Net::DNS::RR is found in records array", records => [""],zone => "test.com");
h_match("something which is not an Net::DNS::RR is found in records array", records => [{}],zone => "test.com");
h_match("something which is not an Net::DNS::RR is found in records array", records => [new Net::DNS::Resolver],zone => "test.com");

sub opt_match
{
	my ($strict,$relaxed,$network,$match,@rest) = @_;

	my %extra;
	for my $s (-1..1) {
		my $smatch = 1;
		$smatch = 0 if $strict;
		if ($s < 0) {
			$extra{strict_checks} = 0;
		} elsif ($s > 0) {
			$extra{strict_checks} = 1;
			$smatch = 1;
		}
		for my $r (-1..1) {
			my $rmatch = 1;
			$rmatch = 0 if $relaxed && !$extra{strict_checks} && $r > 0;
			if ($r < 0) {
				$extra{relaxed_checks} = 0;
			} elsif ($r > 0) {
				$extra{relaxed_checks} = 1;
			}
			for my $n (-1..1) {
				my $nmatch = 1;
				$nmatch = 0 if $network;
				if ($n < 0) {
					$extra{network_checks} = 0;
				} elsif ($n > 0) {
					$extra{network_checks} = 1;
					$nmatch = 1 if $network;
				}
				if ($smatch && $rmatch && $nmatch) {
					h_match($match, %extra, @rest);
				} else {
					h_match("", %extra, @rest);
				}
			}
		}
	}
}

# SOA checks
opt_match(0,0,0, "no SOA records defined", zone => "test.com", records => []);
opt_match(0,0,0, "more than one SOA defined", zone => "test.com", records => [$soa, $soa]);
opt_match(0,0,0, "SOA record name is not the same as zone name", zone => "test.org", records => [$soa]);
# NS checks
opt_match(0,0,0, "no NS records defined", zone => "test.com", records => [$soa]);
opt_match(0,0,0, "NS record is outside the zone", zone => "test.com", records => [$soa,$acme_ns]);
opt_match(0,1,0, "NS record won't be visible due to an existing delegation", zone => "test.com", records => [$soa,$sub_ns,$sub_sub_ns]);
opt_match(0,1,0, "NS record points to an IP address", zone => "test.com", records => [$soa,$ip_ns], network_checks => 0);
opt_match(0,0,0, "", zone => "test.com", records => [$soa,$main_ns,$main_ns2]);
opt_match(0,0,1, "cannot find IP address for NS record", zone => "test.com", records => [$soa,$bad_net_ns,$main_ns]);
opt_match(0,1,0, "NS record points to a non-existing A record inside the zone", zone => "test.com", records => [$soa,$self_ns]);
opt_match(0,1,0, "NS record needs a glue A record", zone => "test.com", records => [$soa,$sub_self_ns]);
opt_match(1,0,0, "less than two NS records for the zone", zone => "test.com", records => [$soa,$main_ns]);
opt_match(1,0,0, "less than two NS records for a subzone", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$sub_ns]);
opt_match(0,0,0, "", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$sub_ns,$sub_ns2]);
# TTL/duplicates
opt_match(1,0,0, "multiple A records for test.com have different TTL values", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$rr_a,$rr_a_ttl]);
opt_match(1,0,0, "duplicate A records for test.com", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$rr_a,$rr_a]);
opt_match(0,0,0, "", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$rr_a,$rr_a2]);
opt_match(1,0,0, "multiple TXT records for test.com have different TTL values", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$rr_txt,$rr_txt_ttl]);
opt_match(1,0,0, "duplicate TXT records for test.com", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$rr_txt,$rr_txt]);
opt_match(0,0,0, "", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$rr_txt,$rr_txt2]);
# all records checks
opt_match(0,0,0, "A record is outside the zone", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$rr_a_out]);
opt_match(0,0,0, "TXT record is outside the zone", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$rr_txt_out]);
opt_match(0,1,0, "A record won't be visible due to an existing delegation", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$sub_ns,$sub_ns2,$rr_a_ins]);
opt_match(0,1,0, "TXT record won't be visible due to an existing delegation", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$sub_ns,$sub_ns2,$rr_txt_ins]);
opt_match(0,1,0, "A record won't be visible due to an existing delegation", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$sub_ns,$sub_ns2,$rr_a_sub]);
opt_match(0,1,0, "TXT record won't be visible due to an existing delegation", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$sub_ns,$sub_ns2,$rr_txt_sub]);
opt_match(0,0,0, "", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$sub_ns,$sub_ns_del,$rr_a_sub]);
# CNAME checks
opt_match(0,0,0, "multiple CNAME records for cname.test.com", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$cname,$cname2]);
opt_match(0,0,0, "CNAME and other data for test.com", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$cname_other]);
opt_match(0,0,0, "CNAME and other data for sub.test.com", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$cname_other2,$rr_a_sub]);
opt_match(0,1,0, "CNAME record points to an IP address", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$cname_ip]);
opt_match(0,0,0, "CNAME record points to a non-existing record inside the zone", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$cname]);
opt_match(0,0,0, "", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$cname,$rr_a_sub]);
opt_match(0,0,0, "CNAME record points to a CNAME record", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$cname,$cname_sub,$rr_a], relaxed_checks => 0);
opt_match(0,0,0, "", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$cname,$cname_sub,$rr_a], strict_checks => 0, relaxed_checks => 1);
opt_match(0,0,0, "CNAME record does not point to an A record", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$cname,$cname_sub], strict_checks => 0, relaxed_checks => 1);
opt_match(0,0,0, "CNAME record does not point to an A record", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$cname_sub]);
# MX checks
opt_match(0,1,0, "MX record points to an IP address", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$mx_ip]);
opt_match(0,1,0, "MX record points to a CNAME record", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$cname,$rr_a_sub,$mx_cname]);
opt_match(0,0,0, "MX record does not point to an A record", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$mx_main]);
opt_match(0,0,0, "", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$mx_main,$rr_a]);
opt_match(0,0,0, "MX record points to a non-existing record inside the zone", zone => "test.com", records => [$soa,$main_ns,$main_ns2,$mx_cname]);
# PTR checks
opt_match(0,0,0, "PTR points to an IN-ADDR.ARPA zone", zone => "3.2.1.in-addr.arpa.", records => [ $soa_ptr, $main_ns_ptr, $main_ns2_ptr, $ptr_inaddr]);
opt_match(0,0,0, "PTR points to an IP6.INT zone", zone => "3.2.1.in-addr.arpa.", records => [ $soa_ptr, $main_ns_ptr, $main_ns2_ptr, $ptr_ip6arpa]);
opt_match(0,0,0, "PTR points to an IP6.INT zone", zone => "3.2.1.in-addr.arpa.", records => [ $soa_ptr, $main_ns_ptr, $main_ns2_ptr, $ptr_ip6int]);
opt_match(0,0,0, "", zone => "3.2.1.in-addr.arpa.", records => [ $soa_ptr, $main_ns_ptr, $main_ns2_ptr, $ptr_ok]);

# comparison checks
my ($cr,$ar,$dr) = Net::DNS::ZoneCheck::compare([$soa,$main_ns,$rr_a], [$soa,$main_ns,$rr_a]);
assert(@$cr == 0 && @$ar == 0 && @$dr == 0, "no difference");
($cr,$ar,$dr) = Net::DNS::ZoneCheck::compare([$soa,$main_ns,$rr_a], [$soa,$main_ns,$rr_a,$rr_a2]);
assert(@$cr == 0 && @$ar == 1 && @$dr == 0 && $ar->[0] eq $rr_a2, "one added");
($cr,$ar,$dr) = Net::DNS::ZoneCheck::compare([$soa,$main_ns,$rr_a,$rr_a2], [$soa,$main_ns,$rr_a]);
assert(@$cr == 0 && @$ar == 0 && @$dr == 1 && $dr->[0] eq $rr_a2, "one removed");
($cr,$ar,$dr) = Net::DNS::ZoneCheck::compare([$soa,$main_ns,$rr_a], [$soa,$main_ns,$rr_a2]);
assert(@$cr == 1 && @$ar == 0 && @$dr == 0 && $cr->[0]->{old} eq $rr_a && $cr->[0]->{new} eq $rr_a2, "one changed");
