use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
	NAME	=> 'Net::DNS::ZoneCheck',
	VERSION_FROM => 'ZoneCheck.pm', # finds $VERSION
	PREREQ_PM => { 'Net::DNS' => 0, 'Regexp::Common' => 0, },
);
