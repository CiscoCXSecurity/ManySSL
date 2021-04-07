#!/usr/bin/perl
=head1 NAME

manyssl.pl - A multiple target SSL cipher checker

=head1 DESCRIPTION

This perl script will enumerate the SSL ciphers in use on any SSL encrypted service, including STARTTLS on SMTP. 
The script will also warn the operator if a self signed certificate is detected.

=head1 USAGE

Usage:  ./manyssl.pl [-h] [-f targets_file] [-m] [-s ip -p port] [-t timeout(secs)] [-c 128] [-x host:port]

        [-h]            this help message
        [-f]            accept a file denoting targets, in the form ip:port
	[-m]		servers are a mailserver; perform starttls
        [-s]            server ip. Accepted forms: single ip 192.168.0.1 or range 192.168.0.1-254 or comma delimited 192.168.0.1,192.168.1.2
        [-p]            port number of ssl service
        [-c 128]        only display ciphers with a key length under 128 bits
	[-r]		highlight weak ciphers in RED?
	[-x]            use a http proxy
	[-g]		only display ciphers not compilant with government standards
        [-t timeout]    alter the timeout value in seconds (default 10 secs)

=head1 UPDATING

update: ./manyssl.pl -u
        updates the cipher DB through openssl

=head1 AUTHOR

Copyright � 22-08-2008 Andy@Portcullis email:tools@portcullis-security.com

=cut

=head1 REQUIREMENTS

Perl Libraries: 

* Net::SSLeay

* Parallel::ForkManager

* Net::Packet::Utils

* IO::Socket::INET

* IO::Socket::SSL

* Term::ANSIColor

* Time::Local

=cut

=head1 LICENSE 

 manyssl - SSL cipher checker
 Copyright � 2008  Portcullis
 
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

#Use Libraries
use Socket;
use Net::SSL;
use Getopt::Std;
use Net::Packet::Utils qw(:all);
use Net::SSLeay qw(get_https post_https sslcat make_headers make_form);
use Parallel::ForkManager;
Net::SSLeay::load_error_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();
$ENV{RND_SEED} = '1234567890123456789012345678901234567890';
Net::SSLeay::randomize();
use IO::Socket::INET;
use IO::Socket::SSL;
use IO::Socket qw(:DEFAULT);
use Term::ANSIColor qw(:constants);
use Time::Local;

#Globals
use vars qw( $VERSION );
my $VERSION = '1.2';
my $gov=0;
my $timeout=10;
my $subj="";
my $issue="";
my $w_ssl=0;
my $proxy_flag=0;

#Get command line flags
my %opts;
getopt('f:t:c:u:h:m:s:p:g:r:x', \%opts);

if (exists $opts{h}){ &usage;}

if (exists $opts{t}){
	if ($opts{t}=~/\d+/){
		$timeout=$opts{t};
	}else{
		die "time in seconds in numeric form\n";
	}
}else{
	$timeout=10;
}

if (exists $opts{m}){
        $starttls=1;
	$timeout=45;
}else{
        $starttls=0;
}

if (exists $opts{r}){
	$color=1;
}else{
        $color=0;
}

if (exists $opts{x}){
        $proxy_flag=1;
	$proxy=$opts{x};
	if ($proxy=~/[a-zA-Z|0-9|\.]+\:\d+/){
		$proxy=~/(.*)\:(\d.*)/;
		$proxy_name = gethostbyname ($1);
 		$proxy_ip=inet_ntoa(inet_aton($1));
		$proxy_port=($2)
	}else{
		die "proxy must be in correct format (host:port)";
	}
}else{
        $proxy_flag=0;
}

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
		if ($host=~/[a-zA-Z|\d|\.]+:\d+/){
			$host=~/(.*):(\d+)/;
			$temp=gethostbyname($1);
			$tem2=inet_ntoa(inet_aton($1));
			
			push(@hosts,$1);
			push(@hosti,$temp);
			push(@hostip,$tem2);
			push(@ports,$2);
		}else{
			die "host file must be in correct format (host:port)";
		}	
	}

}elsif(exists $opts{s}){
	if($opts{s}=~/\d+-\d+/){
		$range=$opts{s};
		@target_list=explodeIps($range);
		foreach $host(@target_list){

			$temp = gethostbyname ($host);
 			$tem2=inet_ntoa(inet_aton($host));

			push(@hosts,$host);
			push(@hosti,$temp);
			push(@hostip,$tem2);
		}
		
	}
	if($opts{s}=~/\d+\,[\d+|\s]\d/){
		@target_list=split(",",$opts{s});
		foreach $host(@target_list){

			$temp = gethostbyname ($host);
 			$tem2=inet_ntoa(inet_aton($host));

			push(@hosts,$host);
			push(@hosti,$temp);
			push(@hostip,$tem2);
		}
	}
	if($opts{s}=~/\d+\.\d+\.\d+\.\d+/){
		$temp = gethostbyname ($opts{s});
 		$tem2=inet_ntoa(inet_aton($opts{s}));

		push(@hosts,$opts{s});
		@target_list=@hosts;
		push(@hosti,$temp);
		push(@hostip,$tem2);
	}else{
		if ($opts{s}=~/\w+\,[\w+|\s]\w/){
			@target_list=split(",",$opts{s});
			foreach $host(@target_list){
				$temp = gethostbyname ($host);
 				$tem2=inet_ntoa(inet_aton($host));

				push(@hosts,$host);
				push(@hosti,$temp);
				push(@hostip,$tem2);
			}
		}else{
		#die "dont know how i got here\n";
		$temp = gethostbyname ($opts{s});
 		$tem2=inet_ntoa(inet_aton($opts{s}));

		push(@hosts,$opts{s});
		@target_list=@hosts;
		push(@hosti,$temp);
		push(@hostip,$tem2);
		}
	}
	if(exists $opts{p}){
		foreach $h(@hosts){
			push(@ports,$opts{p});
		}
	}
	else{
		print "specify port -p X\n";
		&usage;
		exit(0);
	}
}else{
	&usage;
	exit(0);
}

if (exists $opts{c}){
	$c128=$opts{c};
}else{ 
	$c128=0;
}

if (exists $opts{g}){
	$gov=1;
}else{ 
	$gov=0;
}

sub usage{
	print "ManySSL verison $VERSION\n";
	print "Usage: \t$0  [-h] [-f targets_file] [-s ip -p port] [-t timeout(secs)] [-c 128]\n\n";
	print "\t[-h]\t\tthis help message\n";
	print "\t[-f]\t\taccept a file denoting targets, in the form ip:port\n";
	print "\t[-m]\t\tservers are a mailserver; perform starttls\n";
	print "\t[-s]\t\tserver ip. Accepted forms: single ip 192.168.0.1 or range 192.168.0.1-254 or comma delimited 192.168.0.1,192.168.1.2 \n";
	print "\t[-p]\t\tport number of ssl service\n";
	print "\t[-c 128]\tonly display ciphers with a key length under 128 bits\n";
	#print "\t[-g]\t\tonly display ciphers not compilant with government standards\n";
	print "\t[-t timeout]\talter the timeout value in seconds (default 10 secs)\n\n"; 
	print "Update: $0 -u\n\tupdates the cipher DB through openssl\n";
	exit(0);
}#end usage

if (-e "./ciphers.txt"){
	open(FILE,"<ciphers.txt")||die "error";
	@content=<FILE>;
	close(FILE);
	
	foreach $line (@content){
		$_=$line;
		if(/(.*)\w*SSLv3.*Enc=(\S+)\s.*M.*/){
			push(@ssl3,$1);
			push(@ssl3t,$2);
		}
		if(/(.*)\w*SSLv2.*Enc=(\S+)\s.*M.*/){
			push(@ssl2,$1);
			push(@ssl2t,$2);
		}
	}
}else{
	system("openssl ciphers -v ALL:COMPLEMENTOFALL > ciphers.txt")||die "Error: openssl not found!\n";
	print("update complete\n");
	open(FILE,"<ciphers.txt")||die "error";
	@content=<FILE>;
	close(FILE);
	
	foreach $line (@content){
		$_=$line;
		if(/(.*)\w*SSLv3.*Enc=(\S+)\s.*M.*/){
			push(@ssl3,$1);
			push(@ssl3t,$2);
		}
		if(/(.*)\w*SSLv2.*Enc=(\S+)\s.*M.*/){
			push(@ssl2,$1);
			push(@ssl2t,$2);
		}
	};
}
if($starttls==0){
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
	
		&main_sslv3(\$dest_serv_params_test,\$port,\$dest_serv,\$dest_ipint,\@ssl3,\@ssl3t);
		&main_sslv2(\$dest_serv_params_test,\$port,\$dest_serv,\$dest_ipint,\@ssl2,\@ssl2t);
		&main_tlsv1(\$dest_serv_params_test,\$port,\$dest_serv,\$dest_ipint,\@ssl3,\@ssl3t);
		$main_loop->finish;
	}
	$main_loop->wait_all_children;
}#end if
else{
	for ($a=0; $a<@target_list; $a++){
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

		&starttlssub(\$dest_serv_params_test,\$port,\$dest_serv,\$dest_ipint,\@ssl3,\@ssl3t);
	}#end for
}#end else & if-starttls


sub main_sslv3{

my $dest_serv_param_ptr=$_[0];
my $myport_ptr=$_[1];
my $mydest_s_ptr=$_[2];
my $mydest_i_ptr=$_[3];
my $myssl3_ptr=$_[4];
my $myssl3t_ptr=$_[5];
$dest_serv_params=$$dest_serv_param_ptr;
$port=$$myport_ptr;
$dest_serv=$$mydest_s_ptr;
$dest_ipint=$$mydest_i_ptr;
@ssl3=@$myssl3_ptr;
@ssl3t=@$myssl3t_ptr;
$w_ssl=0;

	for($ddd=0; $ddd<@ssl3; $ddd++){
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
			if($proxy_flag){
				Net::SSLeay::set_proxy($proxy_ip, $proxy_port);
			}
			my $res = Net::SSLeay::connect($ssl);
			$_=Net::SSLeay::get_cipher($ssl);

			if (!/.*(NONE)/){
				$cert=Net::SSLeay::dump_peer_certificate($ssl);
                        	if (($w_ssl==0)&&(length($cert)>1)){
                                	if($color==1){print RED, &analyse_cert($cert), RESET;}
					else{print &analyse_cert($cert);}
                                	$w_ssl=1;
                        	}
				if ($c128==128){
					if (@ssl3t[$ddd]=~/256|168|128/){}
					else{
						print "$dest_serv ($dest_ipint):$port - [SSL v3]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n";
					}
				}elsif(($gov==1)&&($c128!=128)){
					if ((@ssl3t[$ddd]=~/256/)||(@ssl3t[$ddd]=~/168/)&&(@ssl3[$ddd]=~/EDH|DHE/)){}
					else{
						print "$dest_serv ($dest_ipint):$port - [SSL v3]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n";
					}
				}else{
					if (@ssl3t[$ddd]=~/256|168|128/){
						print "$dest_serv ($dest_ipint):$port - [SSL v3]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n";
					}
					elsif(@ssl3t[$ddd]=~/ADH/){
						if($color==1){print RED, "$dest_serv ($dest_ipint):$port - [SSL v3]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n", RESET;}
						else{print "$dest_serv ($dest_ipint):$port - [SSL v3]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n";}
					}
					else{
						if($color==1){print RED, "$dest_serv ($dest_ipint):$port - [SSL v3]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n", RESET;}
						else{print "$dest_serv ($dest_ipint):$port - [SSL v3]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n";}
					}
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
			print "[-] $dest_ipint:$port Timed OUT!!!\n";
		}
	
	}#end for
}# end main_sslv3

sub main_sslv2{

my $dest_serv_param_ptr=$_[0];
my $myport_ptr=$_[1];
my $mydest_s_ptr=$_[2];
my $mydest_i_ptr=$_[3];
my $myssl2_ptr=$_[4];
my $myssl2t_ptr=$_[5];
$dest_serv_params=$$dest_serv_param_ptr;
$port=$$myport_ptr;
$dest_serv=$$mydest_s_ptr;
$dest_ipint=$$mydest_i_ptr;
@ssl2=@$myssl2_ptr;
@ssl2t=@$myssl2t_ptr;

	for($ddd=0; $ddd<@ssl2; $ddd++){
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
			if($proxy_flag){
				Net::SSLeay::set_proxy($proxy_ip, $proxy_port);
			}
			$res = Net::SSLeay::connect($ssl);

			$_=Net::SSLeay::get_cipher($ssl);
			if (!/.*(NONE)/){
				if ($c128==128){
					if (@ssl2t[$ddd]=~/256|168|128/){}
					else{
						if($color==1){print RED,"$dest_serv ($dest_ipint):$port - [SSL v2]".Net::SSLeay::get_cipher($ssl)." :@ssl2t[$ddd]\n", RESET;}
						else{print "$dest_serv ($dest_ipint):$port - [SSL v2]".Net::SSLeay::get_cipher($ssl)." :@ssl2t[$ddd]\n";}
					}
				}elsif(($gov==1)&&($c128!=128)){
					if ((@ssl2t[$ddd]=~/256/)||(@ssl2t[$ddd]=~/168/)&&(@ssl3[$ddd]=~/EDH|DHE/)){}
					else{
						if($color==1){print RED,"$dest_serv ($dest_ipint):$port - [SSL v2]".Net::SSLeay::get_cipher($ssl)." :@ssl2t[$ddd]\n", RESET;}
						else{print "$dest_serv ($dest_ipint):$port - [SSL v2]".Net::SSLeay::get_cipher($ssl)." :@ssl2t[$ddd]\n";}
					}
				}else{
					if (@ssl2t[$ddd]=~/256|168|128/){
						if($color==1){print RED,"$dest_serv ($dest_ipint):$port - [SSL v2]".Net::SSLeay::get_cipher($ssl)." :@ssl2t[$ddd]\n", RESET;}
						else{print "$dest_serv ($dest_ipint):$port - [SSL v2]".Net::SSLeay::get_cipher($ssl)." :@ssl2t[$ddd]\n";}
					}
					elsif(@ssl2t[$ddd]=~/ADH/){
						if($color==1){print RED,"$dest_serv ($dest_ipint):$port - [SSL v2]".Net::SSLeay::get_cipher($ssl)." :@ssl2t[$ddd]\n", RESET;}
						else{print "$dest_serv ($dest_ipint):$port - [SSL v2]".Net::SSLeay::get_cipher($ssl)." :@ssl2t[$ddd]\n";}
					}
					else{
						if($color==1){print RED,"$dest_serv ($dest_ipint):$port - [SSL v2]".Net::SSLeay::get_cipher($ssl)." :@ssl2t[$ddd]\n", RESET;}
						else{print "$dest_serv ($dest_ipint):$port - [SSL v2]".Net::SSLeay::get_cipher($ssl)." :@ssl2t[$ddd]\n";}
					}

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
			print "[-] $dest_ipint:$port Timed OUT!!!\n";
		}

	}#end for
}#end main_sslv2

sub main_tlsv1{
my $dest_serv_param_ptr=$_[0];
my $myport_ptr=$_[1];
my $mydest_s_ptr=$_[2];
my $mydest_i_ptr=$_[3];
my $myssl3_ptr=$_[4];
my $myssl3t_ptr=$_[5];
$dest_serv_params=$$dest_serv_param_ptr;
$port=$$myport_ptr;
$dest_serv=$$mydest_s_ptr;
$dest_ipint=$$mydest_i_ptr;
@ssl3=@$myssl3_ptr;
@ssl3t=@$myssl3t_ptr;

	for($ddd=0; $ddd<@ssl3; $ddd++){
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
			if($proxy_flag){
				Net::SSLeay::set_proxy($proxy_ip, $proxy_port);
			}
			$res = Net::SSLeay::connect($ssl);

			$_=Net::SSLeay::get_cipher($ssl);
			if (!/.*(NONE)/){
				if ($c128==128){
					if(@ssl3t[$ddd]=~/256|168|128/){}
					else{
						print "$dest_serv ($dest_ipint):$port - [TLS v1]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n";
					}
				}elsif(($gov==1)&&($c128!=128)){
					if((@ssl3t[$ddd]=~/256/)||(@ssl3t[$ddd]=~/168/)&&(@ssl3[$ddd]=~/EDH|DHE/)){}
					else{
						print "$dest_serv ($dest_ipint):$port - [TLS v1]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n";
					}
				}else{
					if (@ssl3t[$ddd]=~/256|168|128/){
						print "$dest_serv ($dest_ipint):$port - [TLS v1]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n";
					}
					elsif(@ssl3t[$ddd]=~/ADH/){
						if($color==1){print RED, "$dest_serv ($dest_ipint):$port - [TLS v31]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n", RESET;}
						else{print "$dest_serv ($dest_ipint):$port - [TLS v1]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n";}
					}
					else{
						if($color==1){print RED, "$dest_serv ($dest_ipint):$port - [TLS v1]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n", RESET;}
						else{print "$dest_serv ($dest_ipint):$port - [TLS v1]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n";}
					}
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
			print "[-] $dest_ipint:$port Timed OUT!!!\n";
		}
	}#end for

}#end &main_tls_v1

sub starttlssub{

my $dest_serv_param_ptr=$_[0];
my $myport_ptr=$_[1];
my $mydest_s_ptr=$_[2];
my $mydest_i_ptr=$_[3];
my $myssl3_ptr=$_[4];
my $myssl3t_ptr=$_[5];

$dest_serv_params=$$dest_serv_param_ptr;
$port=$$myport_ptr;
$dest_serv=$$mydest_s_ptr;
$dest_ipint=$$mydest_i_ptr;
@ssl3=@$myssl3_ptr;
@ssl3t=@$myssl3t_ptr;

#STARTTLS routine for mail servers
for($ddd=0; $ddd<@ssl3; $ddd++){

	eval {
		local $SIG{ALRM} = sub { die "alarm\n" }; # NB: \n required
		alarm $timeout;

		socket  (S, &AF_INET, &SOCK_STREAM, 0)  or die "socket: $!";
		connect (S, $dest_serv_params)          or die "connect: $!";

		select  (S); $| = 1; select (STDOUT);    
		print S "EHLO $dest_serv\n";
		($a,$b,$c)=get_line(S);
		($a,$b,$c)=get_line(S);
		sleep(5);
		print S "STARTTLS\n";
		sleep(2);
		($a,$b,$c)=get_line(S);

		$ctx = Net::SSLeay::CTX_tlsv1_new() or die_now("Failed to create SSL_CTX $!");
		$ssl = Net::SSLeay::new($ctx) or die_now("Failed to create SSL $!");
		Net::SSLeay::set_cipher_list($ssl, @ssl3[$ddd]) || die("Failed to set SSL cipher list");

		Net::SSLeay::set_fd($ssl, fileno(S));	# Must use fileno
		if($proxy_flag){
			Net::SSLeay::set_proxy($proxy_ip, $proxy_port);
		}
		$res = Net::SSLeay::connect($ssl);
		$_=Net::SSLeay::get_cipher($ssl);

		if (!/.*(NONE)/){
			$cert=Net::SSLeay::dump_peer_certificate($ssl);
                        if (($w_ssl==0)&&(length($cert)>1)){
                                print RED, &analyse_cert($cert), RESET;
                                $w_ssl=1;
                        }
			if ($c128==128){
				if(@ssl3t[$ddd]=~/256|168|128/){}
				else{
					print "$dest_serv ($dest_ipint):$port - [TLS v1]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n";
				}
			}elsif(($gov==1)&&($c128!=128)){
				if((@ssl3t[$ddd]=~/256/)&&(@ssl3[$ddd]=~/EDH|DHE/)){}
				else{
					print "$dest_serv ($dest_ipint):$port - [TLS v1]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n";
				}
			}else{
				print "$dest_serv ($dest_ipint):$port - [TLS v1]".Net::SSLeay::get_cipher($ssl)." :@ssl3t[$ddd]\n";
			}
		}
	
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
		print "[-] $dest_ipint:$port Timed OUT!!!\n";
	}
}#end for
}#end starttls sub

# Get one line of response from the server.
sub get_one_line ($){
my $sock = shift;
my ($code, $sep, $text) = ($sock->getline() =~ /(\d+)(.)([^\r]*)/);
my $more;

	$more = ($sep eq "-");
	if ($verbose)
		{ printf ("[%d] '%s'\n", $code, $text); }
	return ($code, $text, $more);
}

# Get concatenated lines of response from the server.
sub get_line ($){
my $sock = shift;
my ($code, $text, $more) = &get_one_line ($sock);

	while ($more) {
		my ($code2, $line);
		($code2, $line, $more) = &get_one_line ($sock);
		$text .= " $line";
		die ("Error code changed from $code to $code2. That's illegal.\n") if ($code ne $code2);
	}
	return ($code, $text,$more)
;
}

sub analyse_cert{
my $cert=shift;
my $analysis="";
	#$cert=~ s/[\r|\n]/ /;
	if ($cert=~/^Subject\sName:\s(.*)[\r|\n]+Issuer\s+Name:\s(.*)[\r|\n]+/){
		$subj=$1;
		$issue=$2;
		if(($subj eq "undefined")||($issue eq "undefined")){
                       print "ERROR!: Certificate undefined!\n";
		}else{
			if($subj eq $issue){
				print "Certificate info: $subj\n";
				$analysis="WARNING: ($dest_ipint):$port - SELF SIGNED CERTIFICATE! \n";
			}else {
      				$subj=~/O=(.*)\//;
				my $subj_own=$1;
				$issue=~/O=(.*)\//;
				my $iss_own=$1;
				print "Certificate info ($dest_ipint):$port\n$cert";
				if($subj_own eq $iss_own){$analysis="WARNING: ($dest_ipint):$port - SELF SIGNED CERTIFICATE! \n"};
	  		}
		}
	}
	$subj=~/CN=(.*)\//;
	$common=$1;
	if ($common !~/$dest_serv.*/gi){
	$dnsname=gethostbyaddr($dest_ip,AF_INET);
	$digip=gethostbyname($dnsname);
	#print $dnsname." ".$digip." ".$dest_ip;
		if ($common !~/$dnsname/i){
		      
			if($dest_ip !~/$digip/){
				$analysis=$analysis."WARNING: ($dest_ipint):$port - Hostname does not match rDNS Resolution! \n";
			}
		}
	}
	
	my $sock = Net::SSL->new(
			     PeerAddr => $dest_ipint,
			     PeerPort => $port,
			     Timeout => 15,
			     );
	$sock || ($@ ||= "no Net::SSL connection established");
	my $error = $@;
	$error && die("Can't connect to $host:$port; $error; $!");
	my $server_cert = $sock->get_peer_certificate;
	my $enddate = $server_cert->not_after;
	#print "$enddate\n";
		
	@expiredt=split(" |-",$enddate);
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime time;
	$epoch_today = timelocal(0,0,0, $mday,($mon-1),($year+1900));
	$epoch_expire = timelocal(0, 0, 0, $expiredt[2], ($expiredt[1]-1), $expiredt[0]);
	if ($epoch_expire<$epoch_today){
		$analysis=$analysis."WARNING: ($dest_ipint):$port - Certificate Expired! $enddate\n";
	}
 
	return $analysis;
}

$SIG{INT} = \&breakdown;
sub breakdown {
    $SIG{INT} = \&breakdown;
    die "User Termniated\n";
}  
__END__
