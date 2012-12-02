#!/usr/bin/perl
our $VERSION = '1.062';
use strict;
use warnings;
use constant FALSE => 0;
use constant TRUE => 1;
use BGPmon::Log qw(log_init log_fatal log_err log_warn log_notice log_info debug log_close);
use BGPmon::Fetch qw(connect_bgpdata read_xml_message close_connection is_connected);
use BGPmon::Translator::XFB2BGPdump qw(translate_message);
use BGPmon::Configure;
use BGPmon::Filter;
use Net::IP;
use threads qw(yield);
use threads::shared;
use POSIX;
use IO::Handle;
use IO::Socket;
use Regexp::IPv6 qw($IPv6_re);
use Net::Address::IP::Local;

##---- Global Variables
my $progName = $0;
$|=1; #flush every time we print

my $debug;
my $stdoutPrint; #-- keeping track if the user wants to print out results to stdout or not
my $daemon; #will keep track if the uer wants to have the process as a daemon

my @ipv4Prefixes = (); #IPv4 prefixes we want to caputre
my @ipv6Prefixes = ();
my @asNumbers = (); #AS numbers we want to capture

# --- Variables for thread management
my $rThread; #Thread to read from BGPmon
my $pThread; #Parsing Thread
my $tcpListThread; #Listening thread for clients that want to connect
my @tcpReadersQueues = (); #Queues for each client connected to us
my $queueLength;

# ---termination variables and routines.
my $exit = FALSE;
share($exit);



##-- Signal Handlers
$SIG{INT} = $SIG{TERM} = $SIG{KILL} = $SIG{HUP} = \&anyliticsExit;






##--- Variables for Logging ---
#LOG_EMERG	: 0
#LOG_ALERT	: 1
#LOG_CRIT	: 2
#LOG_ERR	: 3
#LOG_WARNING	: 4
#LOG_NOTICE	: 5
#LOG_INFO	: 6
#LOG_DEBUG	: 7

my $logLevel;
my $useSyslog;
my $logFile;



#---  BGPmon variables
my $server; #-- bgpmon server
my $port; #-- bgpmon port (the main port number)

#--- Prefix variables
my $prefixFilename; #-- filename that represents where the prefixes are to be read from

#--- File Output Variables
my $outputFilename; #-- name of the file we want to write to.
my $outputToFile = FALSE; #-- var for user if they want to write to a file


#--- Socket Configuration
my $sock; #-- socket to listen for connecting client
my $myPort; #-- port number that we will listen on






=head1 NAME

bgpmon-filter.pl - Critical Prefix parser

This script can connect to a BGPmon instance and filter messages that match
given critical prefixes.  These messages can then be sent to other clients
that connect to this instance, can be saved to a file, or printed to 
standard out.

=cut

=head1 SYNOPSIS

This script allows one to specify a set of configuration parameters and a list
of desired critical prefixes or autonomous system numbers.  This script will
then connect to the specified instance of BGPmon and filter the messages it
receives.  If a given message has data for one of our given prefixes or any
address within that prefix, it will pass it along to other cliences connected
to it, print it to standard out, or save it to a file.  These are options the
user may set before running an instance.

This will read from a default configuration file located at 
/usr/local/etc/bgpmon-analytics.conf.  Below is an example of a full 
configuration file:

   config_file   =  /usr/local/etc/bgpmon-filter.confg
   output_file   =  /tmp/bgpmon-filter-output.txt
   prefix_file   =  /usr/local/etc/bgpmon-filter-prefixes.conf
   log_file      =  /tmp/bgpmon-filter-log.log
   log_level     =  7
   server        =  bgpmon2.netsec.colostate.edu
   port          =  50001
   listening_port=  60000
   stdout        =  1


This configuration will connect to a BGPmon instance at 
bgpmon2.netsec.colostate.edu:50000 and will listen for connections on 60000.
It will look for a list of critical prefixes to filter in file 
/usr/local/etc/bgpmon-filter-prefixes.conf.  All messages that match the 
prefixes will be printed to standard out and will be saved in file 
/tmp/bgpmon-filter-output.txt.  Note that if you have a configuration file
already and want to change variables for a run, you may do so using command 
line arguments.  They will override any variables set from the configuration 
file.  You may see a list of all options by running ./bgpmon-filter.pl -h.

The following is an example of the critical prefix configuration file:

	ipv4	207.132.222.0/24 ms
	as 	1733
	ipv6 	2a02:1378::/32 ls

You may have multiple prefixes of all kinds and don't have to be in any order
within the file.  For mor information on this file configuration, please see
the perldoc for BGPmon::Filter.pm.


=cut




=head1 AUTHOR

M. Lawrence Weikum, "mweikum@rams.colostate.edu"

=cut

=head1 BUGS

Please report any bugs or feature requests to "bgpmon@netsec.colostate.edu".

=cut


=head1 SUPPORT

You may find documentation help for this script with the perldoc command.
	
	perldoc bgpmon-analytics.pl


=cut

=head1 LICENSE AND COPYRIGHT

Copyright (c) 2012 Colorado State University

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom
the Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

=cut













######################## Main Program ###################################


#--- Checking that the command line arguments and configureation file are set properly.
if(!parseAndCheck()){
	exit 1;
}

if($debug){
	printDebugInfo();
}


# Starting the log file
my $logRetVal = log_init(use_syslog => 0,
			 log_level => $logLevel,
			 log_file => $logFile,
			 prog_name => $progName);
if($logRetVal and defined($logFile)) {
	print STDERR "Error initilaizing log.\n";
	exit 1;
}
log_info("bgpmon-filter has started the log file.");


#Opening output file
if($outputToFile){
	openFile();
	log_info("bgpmon-filter has started the output file to $outputFilename.");
}

# Starting listening socket
print "Opening port for connection to listen in on.\n" if $debug;
my $myAddr = Net::Address::IP::Local->public;
$sock = new IO::Socket::INET (
	LocalHost => $myAddr,
	LocalPort => $myPort,
	Proto => 'tcp',
	Listen => 5,
	Reuse => 1
) or die "Could not create socket for connecting clients.  Aborting.\n" unless $sock;

print "Listening on port $myPort.\n" if $debug;
log_info("Started listening for client connections on $myPort.");

if(BGPmon::Filter::init()){
	print "Coudln't start filter. Aborting\n";
	log_err("Error initializing the filter module.");
	exit 1;
}
log_info("Initialized the filter module.");

if(BGPmon::Filter::parse_config_file($prefixFilename)){
	print "Coudln't parse the filter configuration file.  Aborting\n";
	log_err("Error parsing configuration file $prefixFilename.");
	exit 1;
}
log_info("Parsed configuration file $prefixFilename.");

if($debug){
	print "Active filters:\n";
	BGPmon::Filter::printFilters();
}


# Connecting to BGPmon
print "Connecting to BGPmon\n" if $debug;
my $retVal = connect_bgpdata($server, $port);
if($retVal != 0){
	print "Couldn't connect to the BGPmon server.  Aborting.\n";
	log_err("Coudln't connect to BGPmon server.");
	exit 1;
}
print "Connected to BGPmon server!\n" if $debug;
log_info("Connected to BGPmon server.");


#Daemonizing
if($daemon){
	daemonzie();
}


# Creating shared variables
my @messages, my $printLock;
share(@messages);
share($printLock);
share(@tcpReadersQueues);

# Creating 1 bgpmon listening thread, 3 parsing threads, and 1 TCP accepting thread
$rThread = threads->create('reader');
$pThread = threads->create('parser');
$tcpListThread = threads->create('tcpListener');


$rThread->join();
$pThread->join();
$tcpListThread->join();


#closing the log
log_close();
print "Log file closed.\n" if $debug;





##############################END MAIN PROGRAM#################################




################################PROGRAM START SUBROUTINES#############################


sub parseAndCheck{

	my @params = (
		{
			Name	=> BGPmon::Configure::CONFIG_FILE_PARAMETER_NAME,
			Type	=> BGPmon::Configure::FILE,
			Default => "/usr/local/etc/bgpmon-analytics.conf", 
			Description => "This is the configuration file name.",
		},
		{
			Name => "server",
			Type => BGPmon::Configure::ADDRESS,
			Default => "127.0.0.1",
			Description => "This is the BGPmon server address",
		},

		{
			Name => "port",
			Type => BGPmon::Configure::PORT,
			Default => 50001,
			Description => "This is the BGPmon server port number",
		},

		{
			Name => "listening_port",
			Type => BGPmon::Configure::PORT,
			Default => 60000,
			Description => "This is the port BGPmonAnalytics will listen on",
		},

#		{
#			Name => "queue_length",
#			Type => BGPmon::Configure::UNSIGNED_INT,
#			Default => 1000,
#			Description => "This is the queue length for the connected clients.  If the queue reaches twice this number, this many packets will be dropped.",
#
#		},

		{
			Name => "prefix_file",
			Type => BGPmon::Configure::FILE,
			Default => "/usr/local/etc/bgpmon-analytics-prefixes.conf", 
			Description => "This is the file of critical prefixs the user wants to filter",
		},

		{
			Name => "output_file",
			Type => BGPmon::Configure::FILE,
			Default => "",
			Description => "This is where the BGP XML messages will be saved if the user wants them.",
		},

		{
			Name => "log_file",
			Type => BGPmon::Configure::FILE,
			Default => undef, #Note, undef is convention copied from BGPmon-Archiver
			Description => "This is the location the log file will be saved",
		},

		{
			Name => "log_level",
			Type => BGPmon::Configure::UNSIGNED_INT,
			Default => 7,
			Description => "This is how verbose the user wants the log to be",
		},

		{
			Name => "debug",
			Type => BGPmon::Configure::BOOLEAN,
			Default => FALSE,
			Description => "This is for debugging purposes",
		},

		{
			Name => "daemonize",
			Type => BGPmon::Configure::BOOLEAN,
			Default => FALSE,
			Description => "This will make the make the script run as a daemon",
		},

		{
			Name => "stdout",
			Type => BGPmon::Configure::BOOLEAN,
			Default => FALSE,
			Description => "This is if the user wants to print to standard out",
		} );


	#Checking that everything parsed correctly
	if(BGPmon::Configure::configure(@params) ) {
		my $code = BGPmon::Configure::get_error_code("configure");
		my $msg = BGPmon::Configure::get_error_message("configure");
		print "$code: $msg\n";
		return FALSE;
	}

	#Moving all of the variables into the variables from previous version
	$server = BGPmon::Configure::parameter_value("server");
	$port = BGPmon::Configure::parameter_value("port");
	$myPort = BGPmon::Configure::parameter_value("listening_port");
	$queueLength = BGPmon::Configure::parameter_value("queue_length");
	$debug = BGPmon::Configure::parameter_value("debug");
	$logFile = BGPmon::Configure::parameter_value("log_file");
	$logLevel = BGPmon::Configure::parameter_value("log_level");
	$stdoutPrint = BGPmon::Configure::parameter_value("stdout");
	$prefixFilename = BGPmon::Configure::parameter_value("prefix_file");
	$daemon = BGPmon::Configure::parameter_value("daemonize");
	my $tempOutputFilename = BGPmon::Configure::parameter_value("output_file");
	if($tempOutputFilename eq ""){
		$outputToFile = FALSE;
	}
	else{
		$outputToFile = TRUE;
		$outputFilename = $tempOutputFilename;
	}

	return TRUE;
}


sub printDebugInfo{

	my $config_file = BGPmon::Configure::parameter_value(BGPmon::Configure::CONFIG_FILE_PARAMETER_NAME);

	print "BGPmon Server\t\t$server\n";
	print "BGPmon Port\t\t$port\n";
	print "Listening Port\t\t$myPort\n";
	#print "Queue Length\t\t$queueLength\n";
	print "Configuration File\t$config_file\n";
	print "Critical Prefix File\t$prefixFilename\n";
	print "Output File\t\t$outputFilename\n" if $outputToFile;
	print "Output File\t\t<none>\n" unless $outputToFile;
	print "Log File\t\t$logFile\n" if defined($logFile); #TODO the end of this is a small fix from above.  Waiting on response
	print "Lob Level\t\t$logLevel\n";
	print "Debug\t\t\tTRUE\n" if $debug;
	print "Debug\t\t\tFALSE\n" unless $debug;
	print "Stdout Print\t\tTRUE\n" if $stdoutPrint;
	print "Stdout Print\t\tFALSE\n" unless $stdoutPrint;
	print "Daemonize\t\tTRUE\n" if $daemon;
	print "Daemonize\t\tFALSE\n" unless $daemon;
}


sub openFile{
	open MYFILE, ">>", "$outputFilename" or die "Couldn't open output file $outputFilename.  Aborting.\n";
	log_err("Coudln't open $outputFilename.");
}

sub closeFile{
	close(MYFILE);
}

sub daemonzie {
    # Fork and exit parent. Makes sure we are not a process group leader.
    my $pid = fork;
    exit 0 if $pid;
    exit 1 if not defined $pid;

    # Become leader of a new session, group leader of new
    # process group and detach from any terminal.
    setsid();
    $pid = fork;
    exit 0 if $pid;
    exit 1 if not defined $pid;
}



#################################THREADING SUBROUTINES####################################
#----  Read forever loop that will listen for new TCP connections and spawn a tcpThread per connection
sub tcpListener{

	print "TCPListener thread running and awaiting connections.\n" if $debug;
	log_info("bgpmon-filter is listening for connections.");

	while(!$exit){
		my $new_sock = $sock->accept();
		my $tcpReader = threads->create('tcpThread', $new_sock);
		log_info("Accepted new connection.");
	}

	$sock->close();

	print "TCP connection listner closed.\n" if $debug;
	log_info("Stopped listening for new connections.");

}

#----  Thread that is spawned to handle connection from another client that wants to listen to results.
sub tcpThread{
	print "TCPThread Spawned and Running.\n" if $debug;
	my $mySock = shift;
	my @queue = ();
	my $myQueue = \@queue; #this is a refrence to the queue
	share($myQueue);
	{
		lock(@tcpReadersQueues);
		push(@tcpReadersQueues, $myQueue);
	}

	#Sending intial <xml> to the stream for data processing
	my $myXMLtag = '<xml>';

	$mySock->send($myXMLtag);


	while(!$exit){
		my $nextMsg = undef;
		#print "Thread looking for messages.\n" if $debug;
		{
			lock($myQueue);

			my $queueSize = scalar(@queue);
			if($queueSize > 0){
				$nextMsg = $queue[0];
				shift(@queue);
			}
		}
		# If nothing was on the queue, sleep and yield the processor
		if(!defined($nextMsg)) {
			yield();
			next;
		}
		else{
			my $retvar = $mySock->send($$nextMsg);
		}

	}

	$mySock->close();
	print "Socket closed. TCPconnectionHandler thread finished.\n" if $debug;
	log_info("Client disconnected.");

}




#----  Read forever loop that will receive data from BGPmon ----
sub reader{
	my $xmlMsg = "";
	my $msgType;
	my $write = 0;
	my $count = 0;

	while(!$exit){
		$SIG{'INT'} = sub {print "Exiting\n"; threads->exit();};


		if(!is_connected){
			print "Lost connection to BGPmon. Stopping.\n" if $debug;
			log_info("Lost connection to BGPmon.  Stopping.");
			$exit = TRUE;
			next;
		}

		$xmlMsg = read_xml_message();

		# Check if we received an XML message
		if(!defined $xmlMsg){
			log_err("Error reading XML messgae from BGPmon");
		}

		# Adding message to message queue
		{
			lock (@messages);
			my $tempRef = \$xmlMsg;
			share($tempRef);
			push(@messages, $tempRef);
		}
	}

	print "Exiting reading thread.\n" if $debug;

	# closing connection to BGPmon
	close_connection();
	print "Connection to bgpmon instance closed.\n" if $debug;
	log_info("Connection to bgpmon instance closed.");
}

#---- Read forever loop that will take a message off of the message queue and check to see if we should print it out.  If so, it will.
sub parser{
	while(!$exit){

		# Getting Message
		my $nextMsg = "";
		{
			lock(@messages);
			$nextMsg = $messages[0];
			shift(@messages);
		}

		# If nothing was on the queue, sleep and yield the processor
		if(!defined($nextMsg) or $nextMsg eq "" ) {
			yield();
			sleep(1);
			next;
		}


		#Checking to see if the message has addresses/AS#'s we want, then handling message to stdout, clients, and file.
		if(BGPmon::Filter::matches($$nextMsg)){
			{
				lock($printLock);
				print "$$nextMsg\n\n" if $stdoutPrint;
			}

			# Locking all the queues to tcpReaders and adding the message to their queues
			{
				lock(@tcpReadersQueues);
				foreach my $queue (@tcpReadersQueues){
					#lock($queue);
					push(@$queue, $nextMsg);
				}
			}

			if($outputToFile){
				print MYFILE $$nextMsg;
				MYFILE->autoflush(1);
			}

		}


		#Memory Management
		$$nextMsg = undef;
		$nextMsg = undef;

	}

	print "Parser thread finished.\n" unless !$debug

}

sub anyliticsExit{
	print "\nCaught exit signal.  Quitting.\n";
	{
		$exit = TRUE;
	}
};


