# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42)
# <tobez@tobez.org> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Anton Berezin
# ----------------------------------------------------------------------------
#
# $Id$
#
package Net::DNS::ZoneCheck;
# documentation at the __END__ of the file

use strict;
use 5.005;
use vars qw($VERSION);
use Net::DNS;
use Regexp::Common;

$VERSION = '0.01';

sub check
{
	my %p;

	if (@_ == 2 && ref $_[0] eq "ARRAY") {
		%p = (records => $_[0], zone => $_[1], network_checks => 0, strict_checks => 0, relaxed_checks => 0);
		setup_error_handler(\%p);
	} elsif (@_ % 2 == 0) {
		%p = @_;
		setup_error_handler(\%p);
		eval {
			unless (defined $p{records} && ref $p{records} eq "ARRAY") {
				error(%p, error => "records parameter absent or bad");
			}
			unless (defined $p{zone}) {
				error(%p, error => "zone parameter required");
			}
		};
		if ($@) {
			return undef if $p{soft_errors};
			die;
		}
	} else {
		setup_error_handler(\%p);
		error(%p, error => "bad parameters");
	}

	$p{relaxed_checks} = 0 if $p{strict_checks};

	$p{zone} = normalize_name($p{zone});

	eval {
		for my $rr (@{$p{records}}) {
			error(%p, error => "something which is not an Net::DNS::RR is found in records array", error_record => $rr)
				unless ref($rr) && UNIVERSAL::isa($rr, "Net::DNS::RR");
		}
		$p{by_name} = rrs_by_name($p{records});
		$p{by_type} = rrs_by_type($p{records});
		$p{by_nt} = rrs_by_name_and_type($p{records});

		# any SOA records defined for the zone?
		unless ($p{by_type}->{SOA} && @{$p{by_type}->{SOA}}) {
			error(%p, error => "no SOA records defined");
		}

		# more than one SOA?
		if (@{$p{by_type}->{SOA}} > 1) {
			error(%p, error => "more than one SOA defined");
		}

		# SOA record must belong to the zone itself
		my $soa = $p{by_type}->{SOA}->[0];
		my $name = normalize_name($soa->name);
		if ($name ne $p{zone}) {
			error(%p, error => "SOA record name is not the same as zone name", error_record => $soa);
		}

		# any NS records defined?
		unless ($p{by_type}->{NS} && @{$p{by_type}->{NS}}) {
			error(%p, error => "no NS records defined");
		}

		$p{delegated} = [];

		# loop through all NS records, do individual checks
		my %ns_names;
		for my $ns (@{$p{by_type}->{NS}}) {
			$name = normalize_name($ns->name);
			$ns_names{$name}++;
			my $nsname = normalize_name($ns->nsdname);
			check_ip_pointers(\%p, $nsname, $ns);
			my $c = classify_name(\%p, $name);
			if ($c eq 'outside') {
				error(%p, error => "NS record is outside the zone", error_record => $ns);
			} elsif ($c eq 'inside_delegated') {
				error(%p, error => "NS record won't be visible due to an existing delegation", error_record => $ns) unless $p{relaxed_checks};
			} else {
				# remember this as a new delegation, if it is
				push @{$p{delegated}}, $name if $c eq 'inside';
				my $nc = classify_name(\%p, $nsname);
				if ($nc eq 'outside') {
					# network check
					if ($p{network_checks}) {
						my $res = new Net::DNS::Resolver;
						my $query = $res->query($nsname, "A");
						my @rr;
						error(%p, error => "cannot find IP address for NS record: " . $res->errorstring, error_record => $ns)
							unless $query;
						for my $rr ($query->answer) {
							push @rr, $rr if $rr->type eq 'A';
						}

						error(%p, error => "cannot find IP address NS record: no A records found", error_record => $ns)
							unless @rr;
					}
				} elsif ($nc eq 'inside' || $nc eq 'zone') {
					# must point to an existing A-record
					error(%p, error => "NS record points to a non-existing A record inside the zone", error_record => $ns)
						unless exists $p{by_nt}->{$nsname}->{A} || $p{relaxed_checks};
				} elsif ($nc eq 'delegated' || $nc eq 'inside_delegated') {
					if ($nsname eq $name || $nsname =~ /\.\Q$name\E$/) {
						# glue A-record must be present
						unless (exists $p{by_nt}->{$nsname}->{A} || $p{relaxed_checks}) {
							error(%p, error => "NS record needs a glue A record", error_record => $ns);
						}
						# remember glue records to not trigger "won't be visible" condition in the future
						for my $a (@{$p{by_nt}->{$nsname}->{A}}) {
							$p{glue}->{"$a"} = 1;
						}
					} else {
						# points to another delegation, cannot check anything
					}
				}
			}
		}
		if ($p{strict_checks}) {
			for my $name (keys %ns_names) {
				if ($ns_names{$name} < 2) {
					my $ns = $p{by_nt}->{$name}->{NS};
					if ($name eq $p{zone}) {
						error(%p, error => "less than two NS records for the zone", error_record => $ns);
					} else {
						error(%p, error => "less than two NS records for a subzone", error_record => $ns);
					}
				}
			}
		}

		# non-consistent TTL/duplicate records?
		if ($p{strict_checks}) {
			for my $n (values %{$p{by_nt}}) {
				for my $t (values %$n) {
					my $ttl;
					my %s;
					for my $rr (@$t) {
						$ttl = $rr->ttl unless $ttl;
						my $type = $rr->type;
						my $name = $rr->name;
						error(%p, error => "multiple $type records for $name have different TTL values", error_record => $rr)
							unless $ttl == $rr->ttl;
						error(%p, error => "duplicate $type records for $name", error_record => $rr)
							if $s{$rr->string};
						$s{$rr->string}++;
					}
				}
			}
		}

		# loop through all records and check them one by one
		for my $rr (@{$p{records}}) {
			my $type = $rr->type;
			next if $type eq 'SOA';  # SOA already checked above
			next if $type eq 'NS';   # NS already checked above

			# check that the name belongs to this zone
			my $name = normalize_name($rr->name);
			my $c = classify_name(\%p, $name);
			if ($c eq 'outside') {
				error(%p, error => "$type record is outside the zone", error_record => $rr);
			} elsif ($c eq 'inside_delegated' || $c eq 'delegated') {
				error(%p, error => "$type record won't be visible due to an existing delegation", error_record => $rr)
					unless $p{relaxed_checks} || $p{glue}->{"$rr"};
			}

			if ($type eq 'CNAME') {
				error(%p, error => "multiple CNAME records for $name", error_record => $rr)
					unless @{$p{by_nt}->{$name}->{CNAME}} == 1;
				error(%p, error => "CNAME and other data for $name", error_record => $rr)
					if @{$p{by_name}->{$name}} != 1;

				my $point = normalize_name($rr->rdatastr);
				check_ip_pointers(\%p, $point, $rr);
				if (this_or_delegated(\%p, $point)) {
					error(%p, error => "$type record points to a non-existing record inside the zone", error_record => $rr)
						unless exists $p{by_name}->{$point};
					if (!exists $p{by_nt}->{$point}->{A}) {
						if ($p{by_nt}->{$point}->{CNAME}) {
							error(%p, error => "$type record points to a CNAME record", error_record => $rr)
								unless $p{relaxed_checks};
						} else {
							error(%p, error => "$type record does not point to an A record", error_record => $rr);
						}
					}
				}
			} elsif ($type eq 'MX') {
				my $point = normalize_name($rr->exchange);
				check_ip_pointers(\%p, $point, $rr);
				if (this_or_delegated(\%p, $point)) {
					error(%p, error => "$type record points to a non-existing record inside the zone", error_record => $rr)
						unless exists $p{by_name}->{$point};
					if (!exists $p{by_nt}->{$point}->{A}) {
						if ($p{by_nt}->{$point}->{CNAME}) {
							error(%p, error => "$type record points to a CNAME record", error_record => $rr)
								unless $p{relaxed_checks};
						} else {
							error(%p, error => "$type record does not point to an A record", error_record => $rr);
						}
					}
				}
			} elsif ($type eq 'PTR') {
				my $point = normalize_name($rr->rdatastr);
				check_ip_pointers(\%p, $point, $rr);
				if ($point =~ /\.in-addr\.arpa$/) {
					error(%p, error => "PTR points to an IN-ADDR.ARPA zone", error_record => $rr);
				} elsif ($point =~ /\.ip6\.(int|arpa)$/) {
					error(%p, error => "PTR points to an IP6.INT zone", error_record => $rr);
				}
			}
		}
	};
	if ($@) {
		return undef if $p{soft_errors};
		die;
	}
}

sub check_ip_pointers
{
	my ($p, $point, $rr) = @_;
	return if $p->{relaxed_checks};
	error(%$p, error => $rr->type . " record points to an IP address", error_record => $rr)
		if $point =~ /^$RE{net}{IPv4}(\.\Q$p->{zone}\E)?$/;
}

sub classify_name
{
	my ($p,$name) = @_;

	return 'zone' if $name eq $p->{zone};
	return 'outside' unless $name =~ /\.\Q$p->{zone}\E$/;
	for my $z (@{$p->{delegated}}) {
		return 'delegated' if $name eq $z;
		return 'inside_delegated' if $name =~ /\.\Q$z\E$/;
	}
	return 'inside';
}

sub this_zone
{
	my ($p,$name) = @_;

	my $r = classify_name($p, $name);
	return $r eq 'zone' || $r eq 'inside';
}

sub this_or_delegated
{
	my ($p,$name) = @_;

	my $r = classify_name($p, $name);
	return $r eq 'zone' || $r eq 'inside' || $r eq 'delegated';
}

sub normalize_name
{
	my ($name) = @_;
	$name = lc $name;
	$name =~ s/\.$//; 
	return $name;
}

sub setup_error_handler
{
	my ($p) = @_;
	$p->{soft_errors} = 1 if $p->{on_error} && !exists $p->{soft_errors};
	$p->{quiet} = 1 if $p->{on_error} && !exists $p->{quiet};
}

sub error
{
	my %p = @_;
	my $msg = $p{error} || "unknown error";
	if ($p{on_error}) {
		$p{on_error}->(%p);
	} else {
		warn "$msg\n" if $p{soft_errors} && !$p{quiet};
	}
	die "$msg\n";
}

sub compare
{
	my ($orrs, $nrrs) = @_;

	my %ont = %{rrs_by_name_and_type($orrs)};
	my %nnt = %{rrs_by_name_and_type($nrrs)};
	my (@cr, @ar, @dr);
	my (%oconsidered, %nconsidered);

	for my $name (keys %nnt) {
		for my $type (keys %{$nnt{$name}}) {
			if (exists($ont{$name}) && exists($ont{$name}->{$type})) {
				my @n = @{$nnt{$name}->{$type}};
				my @o = @{$ont{$name}->{$type}};
				my (@nn, @oo);
				for my $nr (@n) {
					my $ns = $nr->string;
					for my $or (@o) {
						my $os = $or->string;
						next if $oconsidered{$os};
						if ($or->string eq $nr->string) {
							$nconsidered{$ns} = 1;
							$oconsidered{$os} = 1;
							last;
						}
					}
					push @nn, $nr unless $nconsidered{$ns};
				}
				for my $or (@o) {
					push @oo, $or unless $oconsidered{$or->string};
				}
				while (@oo && @nn) {
					my $or = shift @oo;
					my $nr = shift @nn;
					$oconsidered{$or->string} = 1;
					$nconsidered{$nr->string} = 1;
					push @cr, { old => $or, new => $nr };
				}
				while (@oo) {
					my $or = shift @oo;
					$oconsidered{$or->string} = 1;
					push @dr, $or;
				}
				while (@nn) {
					my $nr = shift @nn;
					$nconsidered{$nr->string} = 1;
					push @ar, $nr;
				}
			} else {
				for my $rr (@{$nnt{$name}->{$type}}) {
					push @ar, $rr;
				}
			}
		}
	}
	for my $rr (@$orrs) {
		push @dr, $rr unless $oconsidered{$rr->string};
	}

	return \@cr, \@ar, \@dr;
}

sub rrs_by_name
{
	my ($rrs) = @_;
	my %by_name = ();
	for my $rr (@$rrs) {
		push @{$by_name{$rr->name}}, $rr;
	}
	return \%by_name;
}

sub rrs_by_type
{
	my ($rrs) = @_;
	my %by_type = ();
	for my $rr (@$rrs) {
		push @{$by_type{$rr->type}}, $rr;
	}
	return \%by_type;
}

sub rrs_by_name_and_type
{
	my ($rrs) = @_;
	my %by_nt = ();
	for my $rr (@$rrs) {
		push @{$by_nt{$rr->name}->{$rr->type}}, $rr;
	}
	return \%by_nt;
}

1;

__END__

=head1 NAME

Net::DNS::ZoneCheck -- validate a DNS zone composed of RR records

=head1 SYNOPSIS

  use Net::DNS::ZoneCheck;

  Net::DNS::ZoneCheck::check(\@rrs, $zone);
  Net::DNS::ZoneCheck::check(records => \@rrs, zone => $zone, %other_parameters);
  my ($changed_records, $added_records, $deleted_records) =
    Net::DNS::ZoneCheck::compare(\@rrs1, \@rrs2);

=head1 DESCRIPTION

The module assumes that it deals with well-formed Net::DNS::RR records.
That is, there are no checks to ensure that the records themselves are
correct.  For example, no provisions are made to make sure that
Net::DNS::RR::A record contains a valid IP address.  This is supposed to
be done beforehand by some other means.

=head2 NOTE

Please note, that API of the module as of version 0.01 is in flux and
incompatible changes may be introduced in the future versions.

=head2 check

The check() sub takes the following named parameters:

=over 4

=item B<zone>

A name of the zone being checked.  This is a required parameter.

=item B<records>

A reference to an array of Net::DNS::RR records representing zone
contents.  This is a required parameter.

=item B<on_error>

Optional parameter, the default value is undef.  For the description see
section about error handling below.

=item B<soft_error>

Optional parameter, the default value is false.  For the description see
section about error handling below.

=item B<quiet>

Optional parameter, the default value is false.  For the description see
section about error handling below.

=item B<strict_checks>

Optional parameter, the default value is false.  If set to true,
I<check()> will also perform some checks for conditions that strictly
speaking are not errors, but which better to avoid nevertheless.

=item B<relaxed_checks>

Optional parameter, the default value is false.  If set to true,
I<check()> will not perform some checks for conditions which are not
very critical.  If B<strict_checks> is set, B<relaxed_checks> is assumed
to be false, whether it is specified or not.

=item B<network_checks>

Optional parameter, the default value is false.  If set to true,
I<check()> will perform some checks which involve DNS lookups.

=back

It is also possible, if no other parameters are specified, to call
I<check()> using positional parameters as

	check($records, $zonename);

The I<check()> function goes through zone records and performs the
following checks:

=over 4

=item -

that any SOA records are defined for the zone;

=item -

that there is exactly one SOA record;

=item -

that SOA record is indeed an SOA record for this zone;

=item -

that there are some NS records;

=item -

that all NS records are inside this zone;

=item -

that NS records do not point to an IP address (can be skipped with
B<relaxed_checks>);

=item -

that NS records will be visible, which might not be the case because of
delegations (can be skipped with B<relaxed_checks>);

=item -

that, if an NS record points outside of the zone itself, a successful
DNS lookup for the corresponding A record can be made (only done when
B<network_checks> is true);

=item -

that, if an NS record points inside the zone, it points to an existing A
record (can be skipped with B<relaxed_checks>);

=item -

that, if an NS record is a subzone delegation that points to the subzone
itself or inside the subzone, a corresponding "glue" A-record exists
(can be skipped with B<relaxed_checks>);

=item -

that there are at least two NS records for the zone itself and for every
subzone (only done when B<strict_checks> is true);

=item -

that there are no duplicate identical records (only done when
B<strict_checks> is true);

=item -

that records with identical name and type do not have different TTLs
(only done when B<strict_checks> is true);

=item -

that there are no records with names outside of the zone;

=item -

that there are no "invisible" records due to existing delegations (can
be skipped with B<relaxed_checks>);

=item -

that there is no "CNAME and other data" condition;

=item -

that there are no multiple CNAME records with the same name (this is in
fact a particular case of "CNAME and other data" condition);

=item -

that a CNAME record does not point to an IP address (can be skipped with
B<relaxed_checks>);

=item -

that a CNAME record does not point to a non-existing record inside the
zone;

=item -

that a CNAME record does not point to another CNAME record inside the
zone (can be skipped with B<relaxed_checks>);

=item -

that a CNAME record points to an A record (the previous condition is an
exception from this, if B<relaxed_checks> is true);

=item -

that an MX record does not point to an IP address (can be skipped with
B<relaxed_checks>);

=item -

that an MX record does not point to a non-existing record inside the
zone;

=item -

that an MX record does not point to a CNAME record inside the zone (can
be skipped with B<relaxed_checks>);

=item -

that an MX  record points to an A record (the previous condition is an
exception from this, if B<relaxed_checks> is true);

=item -

that a PTR record does not point to an IP address (can be skipped with
B<relaxed_checks>);

=item -

that a PTR record does not point to an IN-ADDR.ARPA or IP6.INT zone.

=back

It is expected that more checks will be added in the future.

=head2 Error handling

The error handling provided by C<check()> is simplistic, but convoluted.
There are three parameters that control what exactly happens when an
error occurs, B<on_error>, B<soft_errors>, and B<quiet>.  The
B<on_error> parameter allows the caller to specify a custom error
handler.  If it is set, it is always called on any error.  When called,
it is passed a hash, in which three key-value pairs are of relevance:
B<error>, a textual description of the error, B<error_record>, a DNS::RR
which is related to the error, if applicable, and B<zone>, a name of the
zone passed by the caller of C<check()>.  The interplay of B<on_error>,
B<soft_errors>, and B<quiet> is best described by the following table:

   on_error is set
         quiet        true        false         !exist
      soft_errors
         true        return     warn & return   return
         false       die        warn & die      die
         !exist      return     warn & return   return

   on_error is not set
         quiet        true        false         !exist
      soft_errors
         true        return     warn & return  warn & return
         false       die        warn & die     warn & die
         !exist      die        warn & die     warn & die

The values of both B<soft_errors> and B<quiet> when they are not
specified are effectively reset to true if B<on_error> is set (compare
true/true and !exist/!exist in the first table).  The author thinks that
this behavior is the most sensible (remember that B<on_error> is always
called when set).

=head2 compare

The C<compare> sub takes two parameters which must be references to
arrays of Net::DNS::RR records.  It is assumed that both parameters
represent the same zone, probably at different moments of time.  The
subroutine determines what records were added, removed, and modified in
the second input array in comparison with the first.  It returns three
values representing the changed records, the added records, and the
removed records.  The last two returned values are references to arrays
of Net::DNS::RR records, while the returned value for that represents
modified records is a reference to an array of references to hashes,
each containing exactly two pairs: one B<old> key with a Net::DNS::RR
record from the first input parameter, and another with B<new> key with
a Net::DNS::RR record from the second input parameter.

=head1 HISTORY

The basic module functionality was first described as a collection of
small examples in my talk "Keeping your DNS sane with Perl" presented at
Nordic Perl Workshop 2004 in Copenhagen.  Nicholas Clark suggested to me
to make a module out of it.

=head1 COPYRIGHT AND LICENSE

Copyright 2004 by Anton Berezin

 "THE BEER-WARE LICENSE" (Revision 42)
 <tobez@tobez.org> wrote this module.  As long as you retain this notice
 you can do whatever you want with this stuff. If we meet some day, and
 you think this stuff is worth it, you can buy me a beer in return.

 Anton Berezin

=head1 CREDITS

This module was largely inspired by a module of a similar functionality
implemented by me for catpipe Systems ApS as a part of a DNS management
system for France Telecom.

=head1 SEE ALSO

Net::DNS(3), Net::DNS::RR(3), Net::DNS::ZoneFile(3), Net::DNS::ZoneFile::Fast(3).

=cut
