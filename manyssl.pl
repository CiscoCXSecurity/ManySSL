#!/usr/bin/perl
=head1 NAME

manyssl.pl - A multiple target SSL cipher checker

=head1 DESCRIPTION

This perl script will enumerate the SSL ciphers in use on any SSL encrypted service.

=head1 USAGE

./manyssl.pl -f [targets_file] -c [128]

./manyssl.pl -u 

=head1 AUTHOR

Copyright © 01-08-2007 Andy Portcullis tools@portcullis-security.com

=cut

=head1 REQUIREMENTS

Perl Libraries: 

* Net::SSLeay

* Parallel::ForkManager

=cut

=head1 LICENSE 

 manyssl - SSL cipher checker
 Copyright © 2007  Portcullis
 
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License along
 with this program; if not, write to the Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

 You are encouraged to send comments, improvements or suggestions to
 me at tools@portcullis-security.com

=cut

use Socket;
use Getopt::Std;
use Net::SSLeay;
use Parallel::ForkManager;
Net::SSLeay::load_error_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();
$ENV{RND_SEED} = '1234567890123456789012345678901234567890';
Net::SSLeay::randomize();

use vars qw( $VERSION );
$VERSION = '1.0';

my %opts;
getopt('f:c:u:h', \%opts);

if (exists $opts{h}){ &usage;}

if (exists $opts{u}) { 
	system("openssl ciphers -v ALL:COMPLEMENTOFALL > ciphers.txt");
	print("update complete!\n");
	exit(1);
}

if (exists $opts{f}){ 
	$targets = $opts{f};
	open(FILE,"<$targets");
	@target_list=<FILE>;
	close(FILE);
	foreach $host(@target_list){
		if ($host=~/.+\:\d+/){
		$host=~/(.*)\:(\d.*)/;
		$temp = gethostbyname ($1);
 		$tem2=inet_ntoa(inet_aton($1));

		push(@hosts,$1);
		push(@hosti,$temp);
		push(@hostip,$tem2);
		push(@ports,$2);
		}else{
			die "host file must be in correct format (host:port)";
		}
	}

}else{
	print "No server specified error\n";
	exit(0);
}


if (exists $opts{c}){
	$c128=$opts{c};
}else{ $c128=0;}


sub usage{
print "Usage: \t$0 -f [targets_file] -c [128]\n";
print "\n\t[128] only display ciphers with a key length under 128 bits\n\n";
print "Update: $0 -u\n\tupdates the cipher DB through openssl\n";
exit(0);
}

if (-e "./ciphers.txt"){
	open(FILE,"<ciphers.txt")||die "error";
	@content=<FILE>;
	close(FILE);
	foreach $line (@content){
		$_=$line;
		if(/(.*)\w*SSLv3.*Enc=(.........).*M.*/){
			push(@ssl3,$1);
			push(@ssl3t,$2);
		}
		if(/(.*)\w*SSLv2.*Enc=(.........).*M.*/){
			push(@ssl2,$1);
			push(@ssl2t,$2);
		}
	}
}else{
	system("openssl ciphers -v ALL:COMPLEMENTOFALL > ciphers.txt");
	print("update complete\n");
	open(FILE,"<ciphers.txt")||die "error";
	@content=<FILE>;
	close(FILE);
	foreach $line (@content){
		$_=$line;
		if(/(.*)\w*SSLv3.*Enc=(.........).*M.*/){
			push(@ssl3,$1);
			push(@ssl3t,$2);
		}
		if(/(.*)\w*SSLv2.*Enc=(.........).*M.*/){
			push(@ssl2,$1);
			push(@ssl2t,$2);
		}
	};
}
$main_loop=new Parallel::ForkManager(20);
for ($a=0; $a<@target_list; $a++){
	$main_loop->start and next;
	$dest_serv=$hosts[$a];
	$dest_ip=$hosti[$a];
	$dest_ipint=$hostip[$a];
	$port=$ports[$a];
	$dest_serv_params_test = sockaddr_in($port, $dest_ip);
	socket  (S, &AF_INET, &SOCK_STREAM, 0)  or die "socket: $!";
	connect (S, $dest_serv_params_test)          or die "[!] ".$dest_ipint.":".$port." - CLOSED!\n";
	select  (S); $| = 1; select (STDOUT);
	shutdown S, 1;  			# Half close --> No more output, sends EOF to server
	close S;
	&main(\$dest_serv_params_test,\$port,\$dest_serv,\$dest_ipint,\@ssl3,\@ssl3t,\@ssl2,\@ssl2t);
	$main_loop->finish;
}
$main_loop->wait_all_children;


sub main{

my $dest_serv_param_ptr=$_[0];
my $myport_ptr=$_[1];
my $mydest_s_ptr=$_[2];
my $mydest_i_ptr=$_[3];
my $myssl3_ptr=$_[4];
my $myssl3t_ptr=$_[5];
my $myssl2_ptr=$_[6];
my $myssl2t_ptr=$_[7];
$dest_serv_params=$$dest_serv_param_ptr;
$port=$$myport_ptr;
$dest_serv=$$mydest_s_ptr;
$dest_ipint=$$mydest_i_ptr;
@ssl3=@$myssl3_ptr;
@ssl3t=@$myssl3t_ptr;
@ssl2=@$myssl2_ptr;
@ssl2t=@$myssl2t_ptr;

for($ddd=0; $ddd<@ssl3; $ddd++){
	$timeout=10;
	eval {
	local $SIG{ALRM} = sub { die "alarm\n" }; # NB: \n required
	alarm $timeout;

	socket  (S, &AF_INET, &SOCK_STREAM, 0)  or die "socket: $!";
	connect (S, $dest_serv_params)          or die "connect: $!";
	select  (S); $| = 1; select (STDOUT);

	my $ctx = Net::SSLeay::CTX_v3_new() or die_now("Failed to create SSL_CTX $!");
	my $ssl = Net::SSLeay::new($ctx) or die_now("Failed to create SSL $!");
	Net::SSLeay::set_cipher_list($ssl, @ssl3[$ddd]) || die("Failed to set SSL cipher list");
	Net::SSLeay::set_fd($ssl, fileno(S));	# Must use fileno
	my $res = Net::SSLeay::connect($ssl);
	$_=Net::SSLeay::get_cipher($ssl);
	if (!/.*(NONE)/){

		if ($c128==128){
			if (@ssl3t[$ddd]=~/256|168|128/){}
			else{
				print "$dest_serv ($dest_ipint):$port - [SSL v3]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n";

			}
		}else{
				print "$dest_serv ($dest_ipint):$port - [SSL v3]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n";

		}
	}

	$res = Net::SSLeay::write($ssl, $msg);  # Perl knows how long $msg is
	shutdown S, 1;  			# Half close --> No more output, sends EOF to server
	$got = Net::SSLeay::read($ssl);         # Perl returns undef on failure

	Net::SSLeay::free ($ssl);               # Tear down connection
	Net::SSLeay::CTX_free ($ctx);
	close S;

	alarm 0;
	};
	if ($@) {
		die unless $@ eq "alarm\n";   # propagate unexpected errors
    		# timed out
		print "[-] Timed OUT!!!\n";
	}
	
}

for($ddd=0; $ddd<@ssl2; $ddd++){

	$timeout=10;
	eval {
	local $SIG{ALRM} = sub { die "alarm\n" }; # NB: \n required
	alarm $timeout;

	socket  (S, &AF_INET, &SOCK_STREAM, 0)  or die "socket: $!";
	connect (S, $dest_serv_params)          or die "connect: $!";
	select  (S); $| = 1; select (STDOUT);

	$ctx = Net::SSLeay::CTX_v2_new() or die_now("Failed to create SSL_CTX $!");
	$ssl = Net::SSLeay::new($ctx) or die_now("Failed to create SSL $!");
	Net::SSLeay::set_cipher_list($ssl, @ssl2[$ddd]) || die("Failed to set SSL cipher list");

	Net::SSLeay::set_fd($ssl, fileno(S));	# Must use fileno
	$res = Net::SSLeay::connect($ssl);

	$_=Net::SSLeay::get_cipher($ssl);
	if (!/.*(NONE)/){
		if ($c128==128){
			if (@ssl2t[$ddd]=~ /256|168|128/){}
			else{
				print "$dest_serv ($dest_ipint):$port - [SSL v2]".Net::SSLeay::get_cipher($ssl)." :@ssl2t[$ddd]\n";

			}
		}else{
			print "$dest_serv ($dest_ipint):$port - [SSL v2]".Net::SSLeay::get_cipher($ssl)." :@ssl2t[$ddd]\n";

		}
	}

	$res = Net::SSLeay::write($ssl, $msg);  # Perl knows how long $msg is
	shutdown S, 1;  			# Half close --> No more output, sends EOF to server
	$got = Net::SSLeay::read($ssl);         # Perl returns undef on failure

	Net::SSLeay::free ($ssl);               # Tear down connection
	Net::SSLeay::CTX_free ($ctx);
	close S;

	alarm 0;
	};
	if ($@) {
		die unless $@ eq "alarm\n";   # propagate unexpected errors
    		# timed out
		print "[-] Timed OUT!!!\n";
	}

}

for($ddd=0; $ddd<@ssl3; $ddd++){

	$timeout=10;
	eval {
	local $SIG{ALRM} = sub { die "alarm\n" }; # NB: \n required
	alarm $timeout;

	socket  (S, &AF_INET, &SOCK_STREAM, 0)  or die "socket: $!";
	connect (S, $dest_serv_params)          or die "connect: $!";
	select  (S); $| = 1; select (STDOUT);    

	$ctx = Net::SSLeay::CTX_tlsv1_new() or die_now("Failed to create SSL_CTX $!");
	$ssl = Net::SSLeay::new($ctx) or die_now("Failed to create SSL $!");
	Net::SSLeay::set_cipher_list($ssl, @ssl3[$ddd]) || die("Failed to set SSL cipher list");

	Net::SSLeay::set_fd($ssl, fileno(S));	# Must use fileno
	$res = Net::SSLeay::connect($ssl);

	$_=Net::SSLeay::get_cipher($ssl);
	if (!/.*(NONE)/){
		if ($c128==128){
			if(@ssl3t[$ddd]=~ /256|168|128/){}
			else{
				print "$dest_serv ($dest_ipint):$port - [TLS v1]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n";
			}
		}else{
			print "$dest_serv ($dest_ipint):$port - [TLS v1]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n";
		}
	}

	$res = Net::SSLeay::write($ssl, $msg);  # Perl knows how long $msg is
	shutdown S, 1;  			# Half close --> No more output, sends EOF to server
	$got = Net::SSLeay::read($ssl);         # Perl returns undef on failure
	Net::SSLeay::free ($ssl);               # Tear down connection
	Net::SSLeay::CTX_free ($ctx);
	close S;

	alarm 0;
	};
	if ($@) {
		die unless $@ eq "alarm\n";   # propagate unexpected errors
    		# timed out
		print "[-] Timed OUT!!!\n";
	}
}
}
__END__
