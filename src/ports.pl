use strict;
use warnings;
use 5.020;

BEGIN { $SIG{INT} = $SIG{TERM} = sub { exit 0 } }

use Getopt::Long;
use Pod::Usage;
use Net::Address::IP::Local;
use IO::Socket::INET;
use List::Util "shuffle";
use Net::Pcap;
use POSIX qw/WNOHANG ceil/;
use Net::RawIP;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use Socket;

#So \r works properly
$| = 1;

use constant CHILDREN => 50;

#Parses cli args and assigns them to variables
GetOptions (
    "help|?" => sub {pod2usage(2)},
    "ip=s"   => \my $target_ip,
);

#Validate cli input
die("Missing --ip parameter, try --help\n") unless $target_ip;

#Gets the local ip address
my $local_ip = Net::Address::IP::Local->public;
#Find a random free port (will be replaced by meow.pl being integrated)
my $local_port = do { 
    my $socket = IO::Socket::INET->new(Proto => "tcp", LocalAddr => $local_ip);
    my $socket_port = $socket->sockport();
    $socket->close;
    $socket_port;
};

#Creates a hash for the named ports in the nmap file supplied by IANA.
my %port_directory;
open(my $port_file, "<", "nmap-services.txt")
    or die("Error reading nmap-services.txt $!\n");

#Load the elements of the nmap file into a hash map
while(<$port_file>) {
    next if /^#/; #Skips comments
    chomp;
    my ($name, $number_protocol, $probability, $comments) = split /\t/;
    my ($port, $proto) = split /\//, $number_protocol;
    
    $port_directory{$number_protocol} = {
        port => $port,
        proto => $proto,
        name => $name,
        probability => $probability,
        comments => $comments,
    };
}

#Shuffle the hash map
my @ports = shuffle do {
    map { $port_directory{$_}->{port} }
    grep { $port_directory{$_}->{name} !~ /^unknown$/
    && $port_directory{$_}->{proto} eq "tcp" } keys %port_directory;
};

#Apportion the ports to scan between processes
my $batch_size = ceil(@ports / CHILDREN);
my %total_ports = map { $_ => "filtered" } @ports; #For reporting
my @child_pids;

for(1. , CHILDREN) {
    my @ports_to_scan = splice @ports, 0, $batch_size;
    my $parent = fork;
    die("Unable to fork!\n") unless defined ($parent);

    if($parent) {
        push(@child_pids, $parent);
        next;
    }

    #Child waits until the parent signals to continue
    my $continue = 0;
    local $SIG{CONT} = sub { $continue = 1 };
    until ($continue) {}

    for my $target_port (@ports_to_scan) {
        sleep(1);
        send_packet($target_port);
    }
    exit 0; #Exit child
}

#Setup parent packet capture
my $device_name = pcap_lookupdev(\my $err);
pcap_lookupnet($device_name, \my $net, \my $mask, \$err);
my $pcap = pcap_open_live($device_name, 1024, 0, 1000, \$err);
pcap_compile(
    $pcap,
    \my $filter,
    "(src net $target_ip) && (dst port $local_port)",
    0,
    $mask
);
pcap_setfilter($pcap, $filter);

#Signal the child pids to start sending
kill CONT => $_ for @child_pids;

#Until all children exit
until(waitpid(-1, WNOHANG) == -1) {
    my $packet_capture = pcap_next_ex($pcap, \my %header, \my $packet);

    if ($packet_capture == 1) {
        read_packet($packet);
    }
    elsif ($packet_capture == -1) {
        warn("Libpcap errored while reading a packet\n");
    }
}

sub send_packet {
    my ($target_port) = @_;

    Net::RawIP->new({ ip => {
                saddr => $local_ip,
                daddr => $target_ip,
            },
            tcp => {
                source => $local_port,
                dest   => $target_port,
                syn    => 1,
            },
        })->send;
}

sub read_packet {
    my ($raw_data) = @_;
    my $ip_data = NetPacket::Ethernet::strip($raw_data);
    my $ip_packet = NetPacket::IP->decode($ip_data);

    #Is it TCP
    if ($ip_packet->{proto} == 6) {
        my $tcp = NetPacket::TCP->decode(NetPacket::IP::strip($ip_data));
        my $port = $tcp->{src_port};
        my $port_name = exists $port_directory{"$port/tcp"}
        ? $port_directory{"$port/tcp"}->{name}
        : "";

        if ($tcp->{flags} & SYN) {
            printf(" %5d %-20s %-20s\n", $port, "open", $port_name);
            $total_ports{$port} = "open";
        }
        elsif ($tcp->{flags} & RST) {
            printf(" %5d %-20s %-20s\n", $port, "closed", $port_name);
            $total_ports{$port} = "closed";
        }
    }
}

printf("\n %d ports scanned, %d filtered, %d closed, %d open\n",
    scalar(keys %total_ports),
    scalar(grep { $total_ports{$_} eq "filtered" } keys %total_ports),
    scalar(grep { $total_ports{$_} eq "closed"   } keys %total_ports),
    scalar(grep { $total_ports{$_} eq "open"     } keys %total_ports));

my($ip, $protocol, $port, $port_stop, $mybox, $yourbox, $log);
#Define the protocol to scan with
$protocol = getprotobyname("tcp");

#Define defaults
$ip = "localhost";
$port = 1;
$port_stop = 65535;
$log = "qsopenports.txt";

print("Searching on $ip for open ports...\n");
print("The following ports are open on $ip between port $port and $port_stop:\n");

#Scan ALL ports
while($port < $port_stop) {
    #Connect by passing SOCKET the parameters defined
    socket(SOCKET, PF_INET, SOCK_STREAM, $protocol);
    $yourbox = inet_aton($ip);
    $mybox = sockaddr_in($port, $yourbox);

    #If the port is open, close it. If closed, print that it's closed.
    if(!connect(SOCKET, $mybox)) {
        printf("%d\r", $port);
    }
    else {
        printf("%d <- open\n", $port);
        close(SOCKET) || die("close: $!");
    }
    $port++;
}

END { pcap_close($pcap) if $pcap }


__END__

=head1 NAME

ports - a concurrent tcp/udp port scanner written in Perl.

=head1 SYNOPSIS

ports [options]

   Options:
    --ip,   -i  ip address to scan e.g. 10.30,1.52
    --help, -h  display this help text. RTFM, right?
