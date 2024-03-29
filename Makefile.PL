use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Crypt::AON::Util',
    AUTHOR              => 'Timothy Zander <timothy.zander@alum.rpi.edu>',
    VERSION_FROM        => 'lib/Crypt/AON/Util.pm',
    ABSTRACT_FROM       => 'lib/Crypt/AON/Util.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
		'Carp' => 0,
		'Crypt::Random' => 0,
		'MIME::Base64' => 0,
		'Exporter' => 0,

    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Crypt-AON-Util-*' },
);
