package Crypt::AoN::Util;

use 5.008008;
use strict;
use warnings;
use Carp;
use Crypt::Random qw/ makerandom /;
use MIME::Base64 ();

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Crypt::AoN::Util ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	newKey
	breakString
	addLength_andPad
	remLength_andPad
	largeNumToChar
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.02';


# Preloaded methods go here.
sub remLength_andPad {
	my %params=@_;
	######
	#takes an array, sent as array, passed as reference
	######
	my $length = unpack("L",substr($params{array}->[$#{$params{array}}], (length $params{array}->[$#{$params{array}}]) - 4 ));
	my $runningLength=0;
	for (my $i=0; $i < scalar @{$params{array}}; $i++) {
		if ($runningLength == $length) {
			pop @{$params{array}};
		} elsif ((length $params{array}->[$i]) + $runningLength > $length) {
			substr($params{array}->[$i],$length-$runningLength) = '';
			$runningLength = $length;
		} else {
			$runningLength += length $params{array}->[$i];
		}
	}
}
sub addLength_andPad {
	my %params=@_;
	#####
	#the array must have fixed length elements and all must be that fixed size except the final element(it can be any size less than or equal to the rest of the array
	#you must pass size to the func, this is the max size of elements in array; ie: packet size(should be in bytes, not bits)
	#does not work with size less than 4
	#if padding is undefined will use random bytes, else use the first char of what is passed to padding
	#need to have passed array reference, \@array
	#how to address this?
	#####
	my $padding;
	if (!defined $params{padding}) {
		$padding = 'pack("C",makerandom(Size=>16) & 0xff)';
	} else {
		$padding = 'substr($params{padding},0,1)';
	}
	my $lastPacketSize = length $params{array}->[$#{$params{array}}];
	my $plaintextLength = $params{size} * (scalar @{$params{array}} - 1) + $lastPacketSize;
	if ((($lastPacketSize) + 4) > $params{size}) {
		for (my $i=0; $i<($params{size} - $lastPacketSize); $i++) {
			$params{array}->[$#{$params{array}}] .= eval $padding;
		}
		my $tmp_item='';
		for (my $i=0;$i<($params{size} - 4); $i++) {
			$tmp_item .= eval $padding;
		}
		push @{$params{array}}, $tmp_item . pack("L",$plaintextLength);
	} else {
		my $tmp_item='';
		for (my $i=0; $i < ($params{size} - (($lastPacketSize) + 4)); $i++) {
			$tmp_item .= eval $padding;
		}
		$params{array}->[$#{$params{array}}] .= $tmp_item . pack("L",$plaintextLength);
	}
}
sub breakString {
	my %params=@_;
	my @brokenString=();
	while (length $params{string} > 0) {
		push @brokenString, substr $params{string}, 0, $params{size};
		$params{string} = substr $params{string}, length $brokenString[$#brokenString];
	}
	return @brokenString;
}

sub newKey {
	my %params = @_;
	#Defaults bits to 128 and return to ASCII
	if (defined $params{size} && $params{size} < 0) { 
		carp "Invalid size, setting to default"; 
		delete $params{size};
	}
	if (defined $params{return} && $params{return} ne 'hex' && $params{return} ne 'ascii' && $params{return} ne 'base64' && $params{return} ne 'int') { 
		carp "Invalid return type, setting to default";
		delete $params{return};
	}
	if (!defined $params{size}) { $params{size} = 128 };
	if (!defined $params{return}) { $params{return} = 'ascii' };
	my $key = makerandom(Size=>$params{size});
	if ($params{return} eq 'ascii') {
		my $processedKey=largeNumToChar(size=>$params{size}, number=>$key);
		return $processedKey;
	} elsif ($params{return} eq 'hex') {
		my $processedKey=largeNumToChar(size=>$params{size}, number=>$key);
		my $processedKeyHex = unpack( "H*", $processedKey );
		return $processedKeyHex;
	} elsif ($params{return} eq 'base64') {
		my $processedKey=largeNumToChar(size=>$params{size}, number=>$key);
		my $processedKeyBase64 = MIME::Base64::encode($processedKey,'');
		return $processedKeyBase64;
	} elsif ($params{return} eq 'int') {
		return $key;
	}
}
sub largeNumToChar {
	my %params = @_;
	if (defined $params{size} && $params{size} < 0) { 
		carp "Invalid size, setting to default"; 
		delete $params{size};
	}
	if (!defined $params{size}) { $params{size} = 128 };
	my $charString='';
	for (my $i=$params{size}-8; $i>=0; $i-=8) {
		$charString.= pack( "C", (($params{number} >> $i) & 0xff) );
	}
	return $charString;
}
1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Crypt::AoN::Util - Perl extension for Utility functions for Crypt::AoN

=head1 SYNOPSIS

  use Crypt::AoN::Util qw/:all/;

  $key = newKey(size=>128, return=>'ascii');
  @brokenString = breakString(string=>$string, size=>$size);
  addLength_andPad(array=>\@array, size=>$packetSize);
  remLength_andPad(array=>\@array);
  $charString = largeNumToChar(size=>$size, number=>$number);

=head1 DESCRIPTION

This provides utility functions needed in Crypt::AoN that could not be found elsewhere.  
If there are equivelant functions in some other more general module, please let me know.

$key = newKey(size=>$size,return=>$type)
  'size' is the number of bits to be in the created key.  it can be any value greater than 0, 128 is the default if nothing is passed
  'return' can currently be 'ascii', 'hex', 'base64', or 'int'.  If ascii, the size of the returned value will be exactly that passed, if hex, it will be twice that passed, if base64, 4/3 that passed, if int, the bitsize will be that passed, or possibly a few bits smaller.

@brokenString = breakString(string=>$string, size=>$size)
  This function breaks up a string into an array with each item in the array of length given.  This does no padding, so the last item in the array may be shorter.  Please see addLength_andPad.
  'size' is the number of bytes, or characters each segment should be
  'string' is the string to be broken

addLength_andPad(array=>\@array, size=>$packetSize)
  This function takes an array of strings and appends the total length of all the items in the array to the end of the array, padding with specified characters to make the last item in teh array the same length as the rest of the items.
  'array' is a reference to the array to be processed.  This is processed inline, the array you pass will be changed when the function returns.  The array must conform to a few guidelines to work with this function.  All elements other than the last must be the same length.  The last element must be less than or equal to the size of the rest.  The elements must be at least 4 bytes large.  
  'size' is the packet size in bytes(ie:characters).  this must be greater than 4
  'padding' is a string containing the padding to be used.  The first character of this string will be used to fill all places needing padding.  If this parameter is not passed, each padding byte will be a random character(0x00..0xFF)

remLength_andPad(array=>\@array)
  This function takes an array as proccessed by addLength_andPad and removes the padding and length from it.
  'array' is a reference to the array to be processed.  This is processed inline, the array you pass will be changed when the function returns.  

largeNumToChar((size=>$size, number=>$number)
  This function takes a large number and converts it to a character string which it returns.
  'size' is the number of bits the final character string should have.
  'number' is the number to convert

=head2 EXPORT

None by default.

:all
  newKey()
  breakString()
  addLength_andPad()

=head1 SEE ALSO

perldoc Crypt::AoN
perldoc Crypt::Random

=head1 AUTHOR

Timothy Zander, E<lt>timothy.zander@alum.rpi.eduE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2007 by Timothy Zander

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


=cut
