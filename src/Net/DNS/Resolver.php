<?php

/**
 * Resolver library.  Builds a DNS query packet, sends the packet to the
 * server and parses the reponse.
 *
 */

namespace Plumpboy\EmailValidate\Net\DNS;

use Plumpboy\EmailValidate\Net\DNS\Resolver;

class Resolver
{
    /**
     * An array of all nameservers to query
     *
     * @var array $nameservers
     */
    public $nameservers;
    /**
     * The UDP port to use for the query (default = 53)
     *
     * @var integer $port
     */
    public $port;
    /**
     * The domain in which the resolver client host resides.
     *
     * @var string $domain
     */
    public $domain;
    /**
     * The searchlist to apply to unqualified hosts
     *
     * An array of strings containg domains to apply to unqualified hosts
     * passed to the resolver.
     *
     * @var array $searchlist
     */
    public $searchlist;
    /**
     * The number of seconds between retransmission of unaswered queries
     *
     * @var integer $retrans
     */
    public $retrans;
    /**
     * The number of times unanswered requests should be retried
     *
     * @var integer $retry
     */
    public $retry;
    /**
     * Whether or not to use TCP (Virtual Circuits) instead of UDP
     *
     * If set to 0, UDP will be used unless TCP is required.  TCP is
     * required for questions or responses greater than 512 bytes.
     *
     * @var boolean $usevc
     */
    public $usevc;
    /**
     * Unknown
     */
    public $stayopen;
    /**
     * Ignore TC (truncated) bit
     *
     * If the server responds with the TC bit set on a response, and $igntc
     * is set to 0, the resolver will automatically retransmit the request
     * using virtual circuits (TCP).
     *
     * @var boolean $igntc
     */
    public $igntc;
    /**
     * Recursion Desired
     *
     * Sets the value of the RD (recursion desired) bit in the header. If
     * the RD bit is set to 0, the server will not perform recursion on the
     * request.
     *
     * @var boolean $recurse
     */
    public $recurse;
    /**
     * Unknown
     */
    public $defnames;
    /**
     * Unknown
     */
    public $dnsrch;
    /**
     * Contains the value of the last error returned by the resolver.
     *
     * @var string $errorstring
     */
    public $errorstring;
    /**
     * The origin of the packet.
     *
     * This contains a string containing the IP address of the name server
     * from which the answer was given.
     *
     * @var string $answerfrom
     */
    public $answerfrom;
    /**
     * The size of the answer packet.
     *
     * This contains a integer containing the size of the DNS packet the
     * server responded with.
     *
     * @var string $answersize
     */
    public $answersize;
    /**
     * The number of seconds after which a TCP connection should timeout
     *
     * @var integer $tcp_timeout
     */
    public $tcp_timeout;
    /**
     * The location of the system resolv.conf file.
     *
     * @var string $resolv_conf
     */
    public $resolv_conf = '/etc/resolv.conf';
    /**
     * The name of the user defined resolv.conf
     *
     * The resolver will attempt to look in both the current directory as
     * well as the user's home directory for a user defined resolver
     * configuration file
     *
     * @var string $dotfile
     */
    public $dotfile = '.resolv.conf';
    /**
     * A array of directories to search for the user's resolver config
     *
     * @var string $confpath
     */
    public $confpath;
    /**
     * debugging flag
     *
     * If set to true (non-zero), debugging code will be displayed as the
     * resolver makes the request.
     *
     * @var boolean $debug
     */
    public $debug;
    /**
     * use the (currently) experimental PHP socket library
     *
     * If set to true (non-zero), the Resolver will attempt to use the
     * much more effecient PHP sockets extension (if available).
     *
     * @var boolean $useEnhancedSockets
     */
    public $useEnhancedSockets = true;
    /**
     * An array of sockets connected to a name servers
     *
     * @var array $sockets
     */
    private $sockets;
    /**
     * axfr tcp socket
     *
     * Used to store a PHP socket resource for a connection to a server
     *
     * @var resource $_axfr_sock
     */
    private $_axfr_sock;
    /**
     * axfr resource record list
     *
     * Used to store a resource record list from a zone transfer
     *
     * @var resource $_axfr_rr
     */
    private $_axfr_rr;
    /**
     * axfr soa count
     *
     * Used to store the number of soa records received from a zone transfer
     *
     * @var resource $_axfr_soa_count
     */
    private $_axfr_soa_count;


    /**
     * Initializes the Resolver Object
     *
     * @return DNS\Resolver
     */
    public function __construct($defaults = [])
    {
        $mydefaults = array(
            'nameservers' => array(),
            'port' => '53',
            'domain' => '',
            'searchlist' => array(),
            'retrans' => 5,
            'retry' => 4,
            'usevc' => 0,
            'stayopen' => 0,
            'igntc' => 0,
            'recurse' => 1,
            'defnames' => 1,
            'dnsrch' => 1,
            'debug' => 0,
            'errorstring' => 'unknown error or no error',
            'answerfrom' => '',
            'answersize'=> 0,
            'tcp_timeout' => 120,
        );
        foreach ($mydefaults as $k => $v) {
            $this->{$k} = isset($defaults[$k]) ? $defaults[$k] : $v;
        }
        $this->confpath[0] = getenv('HOME');
        $this->confpath[1] = '.';
        $this->res_init();
    }

    /**
     * res_init() searches for resolver library configuration files and
     * initializes the publicious properties of the resolver object.
     *
     */
    public function res_init()
    {
        $err = error_reporting(0);
        if (file_exists($this->resolv_conf) && is_readable($this->resolv_conf)) {
            $this->read_config($this->resolv_conf);
        }

        foreach ($this->confpath as $dir) {
            $file = $dir.DIRECTORY_SEPARATOR.$this->dotfile;
            if (file_exists($file) && is_readable($file)) {
                $this->read_config($file);
            }
        }

        $this->read_env();

        if (!strlen($this->domain) && sizeof($this->searchlist)) {
            $this->domain = $this->searchlist[0];
        } elseif (! sizeof($this->searchlist) && strlen($this->domain)) {
            $this->searchlist = array($this->domain);
        }
        error_reporting($err);
    }

    /**
     * Reads and parses a resolver configuration file
     *
     * @param string $file The name of the file to open and parse
     */
    public function read_config($file)
    {
        if (is_readable($file)) {
            if (! ($f = fopen($file, 'r'))) {
                $this->error = "can't open $file";
            }
        }

        if (!is_resource($f)) {
            $this->error = "can't open $file";
        } else {
            while (! feof($f)) {
                $line = chop(fgets($f, 10240));
                $line = ereg_replace('(.*)[;#].*', '\\1', $line);
                if (ereg("^[ \t]*$", $line, $regs)) {
                    continue;
                }
                ereg("^[ \t]*([^ \t]+)[ \t]+([^ \t]+)", $line, $regs);
                $option = $regs[1];
                $value = $regs[2];

                switch ($option) {
                    case 'domain':
                        $this->domain = $regs[2];
                        break;
                    case 'search':
                        $this->searchlist[count($this->searchlist)] = $regs[2];
                        break;
                    case 'nameserver':
                        foreach (split(' ', $regs[2]) as $ns) {
                            $this->nameservers[count($this->nameservers)] = $ns;
                        }
                        break;
                }
            }
            fclose($f);
        }
    }

    /**
     * Examines the environment for resolver config information
     */
    public function read_env()
    {
        if (getenv('RES_NAMESERVERS')) {
            $this->nameservers = split(' ', getenv('RES_NAMESERVERS'));
        }

        if (getenv('RES_SEARCHLIST')) {
            $this->searchlist = split(' ', getenv('RES_SEARCHLIST'));
        }

        if (getenv('LOCALDOMAIN')) {
            $this->domain = getenv('LOCALDOMAIN');
        }

        if (getenv('RES_OPTIONS')) {
            $env = split(' ', getenv('RES_OPTIONS'));
            foreach ($env as $opt) {
                list($name, $val) = split(':', $opt);
                if ($val == '') {
                    $val = 1;
                }
                $this->{$name} = $val;
            }
        }
    }

    /**
     * Builds a string containing the current state of the resolver
     *
     * Builds formatted string containing the state of the resolver library suited
     * for display.
     *
     */
    public function string()
    {
        $state  = ";; DNS\Resolver state:\n";
        $state .= ';;  domain       = ' . $this->domain . "\n";
        $state .= ';;  searchlist   = ' . implode(' ', $this->searchlist) . "\n";
        $state .= ';;  nameservers  = ' . implode(' ', $this->nameservers) . "\n";
        $state .= ';;  port         = ' . $this->port . "\n";
        $state .= ';;  tcp_timeout  = ';
        $state .= ($this->tcp_timeout ? $this->tcp_timeout : 'indefinite') . "\n";
        $state .= ';;  retrans  = ' . $this->retrans . '  ';
        $state .= 'retry    = ' . $this->retry . "\n";
        $state .= ';;  usevc    = ' . $this->usevc . '  ';
        $state .= 'stayopen = ' . $this->stayopen . '    ';
        $state .= 'igntc = ' . $this->igntc . "\n";
        $state .= ';;  defnames = ' . $this->defnames . '  ';
        $state .= 'dnsrch   = ' . $this->dnsrch . "\n";
        $state .= ';;  recurse  = ' . $this->recurse . '  ';
        $state .= 'debug    = ' . $this->debug . "\n";

        return $state;
    }

    /**
     * Returns the next request Id to be used for the DNS packet header
     */
    public static function nextid()
    {
        if ($GLOBALS['_Net_DNS_packet_id']++ > 65535) {
            $GLOBALS['_Net_DNS_packet_id'] = 1;
        }

        return $GLOBALS['_Net_DNS_packet_id'];
    }

    /**
     * Gets or sets the nameservers to be queried.
     *
     * Returns the current nameservers if an array of new nameservers is not
     * given as the argument OR sets the nameservers to the given nameservers.
     *
     * Nameservers not specified by ip address must be able to be resolved by
     * the default settings of a new DNS\Resolver.
     *
     */
    public function nameservers($nsa = array())
    {
        $defres = new Resolver();

        if (is_array($nsa)) {
            $a = array();
            foreach ($nsa as $ns) {
                if (preg_match('/^(\d+(:?\.\d+){0,3})$/', $ns)) {
                    $a[] = ($ns == 0) ? '0.0.0.0' : $ns;
                } else {
                    $names = array();
                    if (!preg_match('/\./', $ns)) {
                        if (!empty($defres->searchlist)) {
                            foreach ($defres->searchlist as $suffix) {
                                $names[] = $ns .'.' . $suffix;
                            }
                        } elseif (!empty($defres->domain)) {
                            $names[] = $ns .'.'. $defres->domain;
                        }
                    } else {
                        $names[] = $ns;
                    }
                    $packet = $defres->search($ns);
                    if (is_object($packet)) {
                        $addresses = $this->cname_addr($names, $packet);
                        foreach ($addresses as $b) {
                            $a[] = $b;
                        }
                        $a = array_unique($a);
                    }
                }
            }
            if (count($a)) {
                $this->nameservers = $a;
            }
        }
        return $this->nameservers;
    }

    /**
     * [cname_addr description]
     *
     * @param  [type] $names  [description]
     * @param  [type] $packet [description]
     *
     * @return [type]         [description]
     */
    public function cname_addr($names, $packet)
    {
        $addr = array();
        foreach ($packet->answer as $rr) {
            if (in_array($rr->name, $names)) {
                if ($rr->type == 'CNAME') {
                    $names[] = $rr->cname;
                } elseif ($rr->type == 'A') {
                    // Run a basic taint check.
                    $addr[] = $rr->address;
                }
            }
        }

        return $addr;
    }

    /**
     * Searches nameservers for an answer
     *
     * Goes through the search list and attempts to resolve name based on
     * the information in the search list.
     *
     * @param string $name [The name (LHS) of a resource record to query.]
     * @param string $type [The type of record to query.]
     * @param string $class [The class of record to query.]
     *
     * @return mixed [An object of type DNS\Packet on success,
     *                or false on failure.]
     */
    public function search($name, $type = 'A', $class = 'IN')
    {
        /*
         * If the name looks like an IP address then do an appropriate
         * PTR query.
         */
        if (preg_match('/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/', $name, $regs)) {
            $name = $regs[4].'.'.$regs[3].'.'.$regs[2].'.'.$regs[1].'.in-addr.arpa.';
            $type = 'PTR';
        }

        /*
         * If the name contains at least one dot then try it as is first.
         */
        if (strstr($name, '.')) {
            if ($this->debug) {
                echo ";; search($name, $type, $class)\n";
            }
            $ans = $this->query($name, $type, $class);
            if (is_object($ans) && ($ans->header->ancount > 0)) {
                return $ans;
            }
        }

        /*
         * If the name does not end in a dot then apply the search list.
         */
        $domain = '';
        if ((! preg_match('/\.$/', $name)) && $this->dnsrch) {
            foreach ($this->searchlist as $domain) {
                $newname = "$name.$domain";
                if ($this->debug) {
                    echo ";; search($newname, $type, $class)\n";
                }
                $ans = $this->query($newname, $type, $class);
                if (is_object($ans) && ($ans->header->ancount > 0)) {
                    return $ans;
                }
            }
        }

        /*
         * Finally, if the name has no dots then try it as is.
         */
        if (strpos($name, '.') === false) {
            if ($this->debug) {
                echo ";; search($name, $type, $class)\n";
            }
            $ans = $this->query($name.'.', $type, $class);
            if (is_object($ans) && ($ans->header->ancount > 0)) {
                return $ans;
            }
        }

        /*
         * No answer was found.
         */
        return false;
    }

    /**
     * Queries nameservers for an answer
     *
     * Queries the nameservers listed in the resolver configuration for an
     * answer to a question packet.
     *
     * @param string $name The name (LHS) of a resource record to query.
     * @param string $type The type of record to query.
     * @param string $class The class of record to query.
     *
     * @return mixed an object of type DNS\Packet, regardless of whether the packet
     *               has an answer or not
     */
    public function rawQuery($name, $type = 'A', $class = 'IN')
    {
        /*
         * If the name does not contain any dots then append the default domain.
         */
        if ((strchr($name, '.') < 0) && $this->defnames) {
            $name .= '.' . $this->domain;
        }

        /*
         * If the name looks like an IP address then do an appropriate
         * PTR query.
         */
        if (preg_match('/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/', $name, $regs)) {
            $name = $regs[4].'.'.$regs[3].'.'.$regs[2].'.'.$regs[1].'.in-addr.arpa.';
            $type = 'PTR';
        }

        if ($this->debug) {
            echo ";; query($name, $type, $class)\n";
        }
        $packet = new Packet($this->debug);
        $packet->buildQuestion($name, $type, $class);
        $packet->header->rd = $this->recurse;
        $ans = $this->send($packet);

        return $ans;
    }

    /**
     * Queries nameservers for an answer
     *
     * Queries the nameservers listed in the resolver configuration for an
     * answer to a question packet.
     *
     * @param string $name [The name (LHS) of a resource record to query.]
     * @param string $type [The type of record to query.]
     * @param string $class [The class of record to query.]
     *
     * @return mixed [An object of type DNS\Packet on success,
     *                or false on failure.]
     */
    public function query($name, $type = 'A', $class = 'IN')
    {
        $ans = $this->rawQuery($name, $type, $class);
        if (is_object($ans) && $ans->header->ancount > 0) {
            return $ans;
        }

        return false;
    }

    /**
     * Sends a packet to a nameserver
     *
     * Determines the appropriate communication method (UDP or TCP) and
     * sends a DNS packet to a nameserver.  Use of the this function
     * directly  is discouraged. $packetORname should always be a properly
     * formatted binary DNS packet.  However, it is possible to send a
     * query here and bypass DNS\Resolver::query()
     *
     * @param string $packetORname [A binary DNS packet stream or a
     *                              hostname to query]
     * @param string $qtype [This should not be used]
     * @param string $qclass [This should not be used]
     *
     * @return object DNS\Packet [An answer packet object]
     */
    public function send($packetORname, $qtype = '', $qclass = '')
    {
        $packet = $this->make_query_packet($packetORname, $qtype, $qclass);
        $packet_data = $packet->data();

        if ($this->usevc != 0 || strlen($packet_data > 512)) {
            $ans = $this->send_tcp($packet, $packet_data);
        } else {
            $ans = $this->send_udp($packet, $packet_data);

            if ($ans && $ans->header->tc && $this->igntc != 0) {
                if ($this->debug) {
                    echo ";;\n;; packet truncated: retrying using TCP\n";
                }
                $ans = $this->send_tcp($packet, $packet_data);
            }
        }

        return $ans;
    }

    /**
     * Prints packet data as hex code.
     */
    public function printhex($data)
    {
        $data = '  ' . $data;
        $start = 0;
        while ($start < strlen($data)) {
            printf(';; %03d: ', $start);
            for ($ctr = $start; $ctr < $start+16; $ctr++) {
                if ($ctr < strlen($data)) {
                    printf('%02x ', ord($data[$ctr]));
                } else {
                    echo '   ';
                }
            }
            echo '   ';
            for ($ctr = $start; $ctr < $start+16; $ctr++) {
                if (ord($data[$ctr]) < 32 || ord($data[$ctr]) > 127) {
                    echo '.';
                } else {
                    echo $data[$ctr];
                }
            }
            echo "\n";
            $start += 16;
        }
    }

    /**
     * Sends a packet via TCP to the list of name servers.
     *
     * @param string $packet [A packet object to send to the NS list]
     * @param string $packet_data [The data in the packet as returned by
     *                             the DNS\Packet::data() method]
     * @return object DNS\Packet [Returns an answer packet object]
     */
    public function send_tcp($packet, $packet_data)
    {
        if (! count($this->nameservers)) {
            $this->errorstring = 'no nameservers';
            if ($this->debug) {
                echo ";; ERROR: send_tcp: no nameservers\n";
            }

            return null;
        }
        $timeout = $this->tcp_timeout;

        foreach ($this->nameservers as $ns) {
            $dstport = $this->port;
            if ($this->debug) {
                echo ";; send_tcp($ns:$dstport)\n";
            }
            $sock_key = "$ns:$dstport";
            if (isset($this->sockets[$sock_key]) && is_resource($this->sockets[$sock_key])) {
                $sock = &$this->sockets[$sock_key];
            } else {
                if (! ($sock = @fsockopen(
                    $ns,
                    $dstport,
                    $errno,
                    $errstr,
                    $timeout
                ))) {
                    $this->errorstring = 'connection failed';
                    if ($this->debug) {
                        echo ";; ERROR: send_tcp: connection failed: $errstr\n";
                    }
                    continue;
                }
                $this->sockets[$sock_key] = $sock;
                unset($sock);
                $sock = &$this->sockets[$sock_key];
            }
            $lenmsg = pack('n', strlen($packet_data));
            if ($this->debug) {
                echo ';; sending ' . strlen($packet_data) . " bytes\n";
            }

            if (($sent = fwrite($sock, $lenmsg)) == -1) {
                $this->errorstring = 'length send failed';
                if ($this->debug) {
                    echo ";; ERROR: send_tcp: length send failed\n";
                }
                continue;
            }

            if (($sent = fwrite($sock, $packet_data)) == -1) {
                $this->errorstring = 'packet send failed';
                if ($this->debug) {
                    echo ";; ERROR: send_tcp: packet data send failed\n";
                }
            }

            socket_set_timeout($sock, $timeout);
            $buf = fread($sock, 2);
            $e = socket_get_status($sock);
            /* If $buf is empty, we want to supress errors
               long enough to reach the continue; down the line */
            $len = @unpack('nint', $buf);
            $len = @$len['int'];
            if (!$len) {
                continue;
            }
            $buf = fread($sock, $len);
            $actual = strlen($buf);
            $this->answerfrom = $ns;
            $this->answersize = $len;
            if ($this->debug) {
                echo ";; received $actual bytes\n";
            }
            if ($actual != $len) {
                $this->errorstring = "expected $len bytes, received $buf";
                if ($this->debug) {
                    echo ';; send_tcp: ' . $this->errorstring;
                }
                continue;
            }

            $ans = new Packet($this->debug);
            if (is_null($ans->parse($buf))) {
                continue;
            }
            $this->errorstring = $ans->header->rcode;
            $ans->answerfrom = $this->answerfrom;
            $ans->answersize = $this->answersize;

            return $ans;
        }
    }

    /**
     * Sends a packet via UDP to the list of name servers.
     *
     * This function sends a packet to a nameserver.  It is called by
     * send_udp if the sockets PHP extension is not compiled into PHP.
     *
     * @param string $packet [A packet object to send to the NS list]
     * @param string $packet_data [The data in the packet as returned by the DNS\Packet::data() method]
     *
     * @return object DNS\Packet [Returns an answer packet object]
     */
    public function send_udp_no_sock_lib($packet, $packet_data)
    {
        $retrans = $this->retrans;
        $timeout = $retrans;

        /*
         * PHP doesn't have excellent socket support as of this writing.
         * This needs to be rewritten when PHP POSIX socket support is
         * complete.
         * Obviously, this code is MUCH different than the PERL implementation
         */

        $w = error_reporting(0);
        $ctr = 0;
        // Create a socket handle for each nameserver
        foreach ($this->nameservers as $nameserver) {
            if ($sock[$ctr++] = fsockopen("udp://$nameserver", $this->port)) {
                $peerhost[$ctr-1] = $nameserver;
                $peerport[$ctr-1] = $this->port;
                socket_set_blocking($sock[$ctr-1], false);
            } else {
                $ctr--;
            }
        }
        error_reporting($w);

        if ($ctr == 0) {
            $this->errorstring = 'no nameservers';
            return null;
        }

        for ($i = 0; $i < $this->retry; $i++, $retrans *= 2,
                $timeout = (int) ($retrans / $ctr)) {
            if ($timeout < 1) {
                $timeout = 1;
            }

            foreach ($sock as $k => $s) {
                if ($this->debug) {
                    echo ';; send_udp(' . $peerhost[$k] . ':' . $peerport[$k] . '): sending ' . strlen($packet_data) . " bytes\n";
                }

                if (! fwrite($s, $packet_data)) {
                    if ($this->debug) {
                        echo ";; send error\n";
                    }
                }

                /*
                 *  Here's where it get's really nasty.  We don't have a select()
                 *  function here, so we have to poll for a response... UGH!
                 */

                $timetoTO  = time() + (double)microtime() + $timeout;

                /*
                 * let's sleep for a few hundred microseconds to let the
                 * data come in from the network...
                 */
                usleep(500);
                $buf = '';
                while (! strlen($buf) && $timetoTO > (time() +
                            (double)microtime())) {
                    socket_set_blocking($s, false);
                    if ($buf = fread($s, 512)) {
                        $this->answerfrom = $peerhost[$k];
                        $this->answersize = strlen($buf);
                        if ($this->debug) {
                            echo ';; answer from ' . $peerhost[$k] . ':' .
                                $peerport[$k] .  ': ' . strlen($buf) . " bytes\n";
                        }
                        $ans = new Packet($this->debug);
                        if ($ans->parse($buf)) {
                            if ($ans->header->qr != '1') {
                                continue;
                            }
                            if ($ans->header->id != $packet->header->id) {
                                continue;
                            }
                            $this->errorstring = $ans->header->rcode;
                            $ans->answerfrom = $this->answerfrom;
                            $ans->answersize = $this->answersize;
                            return $ans;
                        }
                    }
                    // Sleep another 1/100th of a second... this sucks...
                    usleep(1000);
                }
            }

            $this->errorstring = 'query timed out';

            return null;
        }
    }

    /**
     * Sends a packet via UDP to the list of name servers.
     *
     * This function sends a packet to a nameserver.  It is called by
     * send_udp if the sockets PHP extension is compiled into PHP.
     *
     * @param string $packet [A packet object to send to the NS list]
     * @param string $packet_data [The data in the packet as returned by the DNS\Packet::data() method]
     *
     * @return object DNS\Packet [Returns an answer packet object]
     *
     */
    public function send_udp_with_sock_lib($packet, $packet_data)
    {
        $retrans = $this->retrans;
        $timeout = $retrans;

        $ctr = 0;
        // Create a socket handle for each nameserver
        foreach ($this->nameservers as $nameserver) {
            if ((($sock[$ctr++] = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP))) &&
                  socket_connect($sock[$ctr-1], $nameserver, $this->port)) {
                $peerhost[$ctr-1] = $nameserver;
                $peerport[$ctr-1] = $this->port;
                socket_set_nonblock($sock[$ctr-1]);
            } else {
                $ctr--;
            }
        }

        if ($ctr == 0) {
            $this->errorstring = 'no nameservers';
            return null;
        }
        // Try each nameserver up to $this->retry times
        for ($i = 0; $i < $this->retry; $i++) {
            if ($i != 0) {
                // Set the timeout for each retry based on the number of
                // nameservers there is a connected socket for.
                $retrans *= 2;
                $timeout = (int) ($retrans / $ctr);
            }
            // Make sure the timeout is at least 1 second
            if ($timeout < 1) {
                $timeout = 1;
            }

            // Try each nameserver
            foreach ($sock as $k => $s) {
                if ($this->debug) {
                    echo "\n;; send_udp(" . $peerhost[$k] . ':' . $peerport[$k] . '): sending ' . strlen($packet_data) . " bytes\n";
                }

                if (! socket_write($s, $packet_data)) {
                    if ($this->debug) {
                        echo ";; send error\n";
                    }
                }

                $set = array($s);
                if ($this->debug) {
                    echo ";; timeout set to $timeout seconds\n";
                }
                $changed = socket_select($set, $w = null, $e = null, $timeout);
                if ($changed) {
                    // Test to see if the connection was refused.  Linux servers will send
                    // an ICMP message which will cause the client's next system call to
                    // return ECONNREFUSED if the server is not listening on the ip:port queried
                    if (socket_get_option($s, SOL_SOCKET, SO_ERROR) == SOCKET_ECONNREFUSED) {
                        // Unix socket connection was refused
                        if ($this->debug) {
                            echo ';; connection to ' . $peerhost[$k] . ':' . $peerport[$k] . " was refused\n";
                        }
                        // Try the next server.
                        continue;
                    }

                    // Read the response
                    $buf = @socket_read($s, 512);
                    if ($buf === false) {
                        // No data could be read from socket
                        if ($this->debug) {
                            echo ';; no data could be read from ' . $peerhost[$k] . ':' . $peerport[$k] . "\n";
                            echo ';; socket_error: ' . socket_strerror(socket_last_error()) . "\n";
                        }
                        // Reset the non-specific socket error status
                        socket_clear_error();
                        // Try the next server.
                        continue;
                    }

                    $this->answerfrom = $peerhost[$k];
                    $this->answersize = strlen($buf);
                    if ($this->debug) {
                        echo ';; answer from ' . $peerhost[$k] . ':' .
                            $peerport[$k] .  ': ' . strlen($buf) . " bytes\n";
                    }
                    $ans = new Packet($this->debug);
                    if ($ans->parse($buf)) {
                        if ($ans->header->qr != '1') {
                            // Ignore packet if it is not a response
                            continue;
                        } elseif ($ans->header->id != $packet->header->id) {
                            // Ignore packet if the response id does not match the query id
                            continue;
                        } else {
                            // Return the DNS response packet
                            $this->errorstring = $ans->header->rcode;
                            $ans->answerfrom = $this->answerfrom;
                            $ans->answersize = $this->answersize;
                            return $ans;
                        }
                    }
                } elseif ($this->debug) {
                    echo ";; query to ". $peerhost[$k] . ':' . $peerport[$k] . " timed out\n";
                }
            }
        }
        $this->errorstring = 'query timed out';

        return null;
    }

    /**
     * Sends a packet via UDP to the list of name servers.
     *
     * This function sends a packet to a nameserver.  send_udp calls
     * either DNS\Resolver::send_udp_no_sock_lib() or
     * DNS\Resolver::send_udp_with_sock_lib() depending on whether or
     * not the sockets extension is compiled into PHP.  Note that using the
     * sockets extension is MUCH more efficient.
     *
     * @param object DNS\Packet $packet [A packet object to send to the NS list]
     * @param string $packet_data [The data in the packet as returned by the DNS\Packet::data() method]
     *
     * @return object DNS\Packet [Returns an answer packet object]
     */
    public function send_udp($packet, $packet_data)
    {
        if (extension_loaded('sockets') && $this->useEnhancedSockets) {
            if ($this->debug) {
                echo "\n;; using extended PHP sockets\n";
            }
            return $this->send_udp_with_sock_lib($packet, $packet_data);
        } else {
            if ($this->debug) {
                echo "\n;; using simple sockets\n";
            }
            return $this->send_udp_no_sock_lib($packet, $packet_data);
        }
    }

    /**
     * Unknown
     */
    public function make_query_packet($packetORname, $type = '', $class = '')
    {
        if (is_object($packetORname) && strcasecmp(get_class($packetORname), Packet::class) == 0) {
            $packet = $packetORname;
        } else {
            $name = $packetORname;
            if ($type == '') {
                $type = 'A';
            }
            if ($class == '') {
                $class = 'IN';
            }

            /*
             * If the name looks like an IP address then do an appropriate
             * PTR query.
             */
            if (preg_match('/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/', $name, $regs)) {
                $name = $regs[4].'.'.$regs[3].'.'.$regs[2].'.'.$regs[1].'.in-addr.arpa.';
                $type = 'PTR';
            }

            if ($this->debug) {
                echo ";; query($name, $type, $class)\n";
            }
            $packet = new Packet($this->debug);
            $packet->buildQuestion($name, $type, $class);
        }

        $packet->header->rd = $this->recurse;

        return $packet;
    }

    /**
     * Performs an AXFR query (zone transfer) (OLD BUGGY STYLE)
     *
     * This is deprecated and should not be used!
     *
     * @param string $dname [The domain (zone) to transfer]
     * @param string $class [The class in which to look for the zone.]
     *
     * @return object DNS\Packet
     */
    public function axfr_old($dname, $class = 'IN')
    {
        return $this->axfr($dname, $class, true);
    }

    /**
     * Performs an AXFR query (zone transfer)
     *
     * Requests a zone transfer from the nameservers. Note that zone
     * transfers will ALWAYS use TCP regardless of the setting of the
     * DNS\Resolver::$usevc flag.  If $old is set to true, DNS requires
     * a nameserver that supports the many-answers style transfer format.  Large
     * zone transfers will not function properly.  Setting $old to true is _NOT_
     * recommended and should only be used for backwards compatibility.
     *
     * @param string $dname [The domain (zone) to transfer]
     * @param string $class [The class in which to look for the zone.]
     * @param boolean $old [Requires 'old' style many-answer format to function.
     *                      Used for backwards compatibility only.]
     * @return object DNS\Packet
     */
    public function axfr($dname, $class = 'IN', $old = false)
    {
        if ($old) {
            if ($this->debug) {
                echo ";; axfr_start($dname, $class)\n";
            }
            if (! count($this->nameservers)) {
                $this->errorstring = 'no nameservers';
                if ($this->debug) {
                    echo ";; ERROR: no nameservers\n";
                }
                return null;
            }
            $packet = $this->make_query_packet($dname, 'AXFR', $class);
            $packet_data = $packet->data();
            $ans = $this->send_tcp($packet, $packet_data);

            return $ans;
        } else {
            if ($this->axfr_start($dname, $class) === null) {
                return null;
            }
            $ret = array();
            while (($ans = $this->axfr_next()) !== null) {
                if ($ans === null) {
                    return null;
                }
                array_push($ret, $ans);
            }

            return $ret;
        }
    }

    /**
     * Sends a packet via TCP to the list of name servers.
     *
     * @param string $packet [A packet object to send to the NS list]
     * @param string $packet_data [The data in the packet as returned by
     *                             the DNS\Packet::data() method]
     * @return object DNS\Packet [Returns an answer packet object]
     */
    public function axfr_start($dname, $class = 'IN')
    {
        if ($this->debug) {
            echo ";; axfr_start($dname, $class)\n";
        }

        if (! count($this->nameservers)) {
            $this->errorstring = "no nameservers";
            if ($this->debug) {
                echo ";; ERROR: axfr_start: no nameservers\n";
            }

            return null;
        }
        $packet = $this->make_query_packet($dname, "AXFR", $class);
        $packet_data = $packet->data();

        $timeout = $this->tcp_timeout;

        foreach ($this->nameservers as $ns) {
            $dstport = $this->port;
            if ($this->debug) {
                echo ";; axfr_start($ns:$dstport)\n";
            }
            $sock_key = "$ns:$dstport";
            if (is_resource($this->sockets[$sock_key])) {
                $sock = &$this->sockets[$sock_key];
            } else {
                if (!($sock = fsockopen(
                    $ns,
                    $dstport,
                    $errno,
                    $errstr,
                    $timeout
                ))) {
                    $this->errorstring = "connection failed";
                    if ($this->debug) {
                        echo ";; ERROR: axfr_start: connection failed: $errstr\n";
                    }
                    continue;
                }
                $this->sockets[$sock_key] = $sock;
                unset($sock);
                $sock = &$this->sockets[$sock_key];
            }
            $lenmsg = pack("n", strlen($packet_data));
            if ($this->debug) {
                echo ";; sending " . strlen($packet_data) . " bytes\n";
            }

            if (($sent = fwrite($sock, $lenmsg)) == -1) {
                $this->errorstring = "length send failed";
                if ($this->debug) {
                    echo ";; ERROR: axfr_start: length send failed\n";
                }
                continue;
            }

            if (($sent = fwrite($sock, $packet_data)) == -1) {
                $this->errorstring = "packet send failed";
                if ($this->debug) {
                    echo ";; ERROR: axfr_start: packet data send failed\n";
                }
            }

            socket_set_timeout($sock, $timeout);

            $this->_axfr_sock = $sock;
            $this->_axfr_rr = array();
            $this->_axfr_soa_count = 0;

            return $sock;
        }
    }

    /**
     * Requests the next RR from a existing transfer started with axfr_start
     *
     * @return object DNS\RR [Returns a DNS\RR object of the next RR
     *                        from a zone transfer.]
     */
    public function axfr_next()
    {
        if (! count($this->_axfr_rr)) {
            if (! isset($this->_axfr_sock) || ! is_resource($this->_axfr_sock)) {
                $this->errorstring = 'no zone transfer in progress';

                return null;
            }
            $timeout = $this->tcp_timeout;
            $buf = $this->read_tcp($this->_axfr_sock, 2, $this->debug);
            if (! strlen($buf)) {
                $this->errorstring = 'truncated zone transfer';

                return null;
            }
            $len = unpack('n1len', $buf);
            $len = $len['len'];
            if (! $len) {
                $this->errorstring = 'truncated zone transfer';

                return null;
            }
            $buf = $this->read_tcp($this->_axfr_sock, $len, $this->debug);
            if ($this->debug) {
                echo ';; received ' . strlen($buf) . "bytes\n";
            }
            if (strlen($buf) != $len) {
                $this->errorstring = 'expected ' . $len . ' bytes, received ' . strlen($buf);
                if ($this->debug) {
                    echo ';; ' . $err . "\n";
                }

                return null;
            }
            $ans = new Packet($this->debug);
            if (! $ans->parse($buf)) {
                if (! $this->errorstring) {
                    $this->errorstring = 'unknown error during packet parsing';
                }

                return null;
            }
            if ($ans->header->ancount < 1) {
                $this->errorstring = 'truncated zone transfer';

                return null;
            }
            if ($ans->header->rcode != 'NOERROR') {
                $this->errorstring = 'errorcode ' . $ans->header->rcode . ' returned';

                return null;
            }
            foreach ($ans->answer as $rr) {
                if ($rr->type == 'SOA') {
                    if (++$this->_axfr_soa_count < 2) {
                        array_push($this->_axfr_rr, $rr);
                    }
                } else {
                    array_push($this->_axfr_rr, $rr);
                }
            }
            if ($this->_axfr_soa_count >= 2) {
                unset($this->_axfr_sock);
            }
        }
        $rr = array_shift($this->_axfr_rr);

        return $rr;
    }

    /**
     * Unknown - not ported yet
     */
    public function read_tcp($sock, $nbytes, $debug = 0)
    {
        $buf = '';
        while (strlen($buf) < $nbytes) {
            $nread = $nbytes - strlen($buf);
            $read_buf = '';
            if ($debug) {
                echo ";; read_tcp: expecting $nread bytes\n";
            }
            $read_buf = fread($sock, $nread);
            if (! strlen($read_buf)) {
                if ($debug) {
                    echo ";; ERROR: read_tcp: fread failed\n";
                }
                break;
            }
            if ($debug) {
                echo ';; read_tcp: received ' . strlen($read_buf) . " bytes\n";
            }
            if (!strlen($read_buf)) {
                break;
            }

            $buf .= $read_buf;
        }

        return $buf;
    }
}