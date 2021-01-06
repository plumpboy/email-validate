<?php
/**
* Class to provide IPv4 calculations
*/

namespace Plumpboy\EmailValidate\Net;

use Plumpboy\EmailValidate\Net\DNS\Header;
use Plumpboy\EmailValidate\Net\DNS\Question;
use Plumpboy\EmailValidate\Net\DNS\Packet;
use Plumpboy\EmailValidate\Net\DNS\Resolver;
use Plumpboy\EmailValidate\Net\DNS\RR;

$GLOBALS['_Net_DNS_packet_id'] = mt_rand(0, 65535);

/**
 * Initializes a resolver object
 *
 * DNS allows you to query a nameserver for DNS  lookups.  It bypasses the
 * system resolver library  entirely, which allows you to query any nameserver,
 * set your own values for retries, timeouts, recursion,  etc.
 *
 */
class DNS
{
    /**
     * A default resolver object created on instantiation
     */
    protected $resolver;
    public static $PACKETSZ = 512;
    public static $HFIXEDSZ = 12;
    public static $QFIXEDSZ = 4;
    public static $RRFIXEDSZ = 10;
    public static $INT32SZ = 4;
    public static $INT16SZ = 2;

    /**
     * Initializes a resolver object
     *
     * @param array $defaults
     */
    public function __construct($defaults = array())
    {
        $this->resolver = new Resolver($defaults);
    }

    /**
     * Translates opcode names to integers
     *
     * Translates the name of a DNS OPCODE into it's assigned  number
     * listed in RFC1035, RFC1996, or RFC2136. Valid  OPCODES are:
     * <ul>
     *   <li>QUERY
     *   <li>IQUERY
     *   <li>STATUS
     *   <li>NS_NOTIFY_OP
     *   <li>UPDATE
     * <ul>
     *
     * @param   string  $opcode A DNS Packet OPCODE name
     * @return  integer The integer value of an OPCODE
     */
    public function opcodesbyname($opcode)
    {
        $op = array(
            'QUERY' => 0, // RFC 1035
            'IQUERY' => 1, // RFC 1035
            'STATUS' => 2, // RFC 1035
            'NS_NOTIFY_OP' => 4, // RFC 1996
            'UPDATE' => 5, // RFC 2136
        );
        if (! strlen($op[$opcode])) {
            $op[$opcode] = null;
        }

        return $op[$opcode];
    }

    /**
     * Translates opcode integers into names
     *
     * Translates the integer value of an opcode into it's name
     *
     * @param integer $opcodeval  A DNS packet opcode integer
     * @return string  The name of the OPCODE
     */
    public static function opcodesbyval($opcodeval)
    {
        $opval = array(
            0 => 'QUERY',
            1 => 'IQUERY',
            2 => 'STATUS',
            4 => 'NS_NOTIFY_OP',
            5 => 'UPDATE',
        );
        if (!strlen($opval[$opcodeval])) {
            $opval[$opcodeval] = null;
        }

        return $opval[$opcodeval];
    }

    /**
     * Translates rcode names to integers
     *
     * Translates the name of a DNS RCODE (result code) into it's assigned number.
     * <ul>
     *   <li>NOERROR
     *   <li>FORMERR
     *   <li>SERVFAIL
     *   <li>NXDOMAIN
     *   <li>NOTIMP
     *   <li>REFUSED
     *   <li>YXDOMAIN
     *   <li>YXRRSET
     *   <li>NXRRSET
     *   <li>NOTAUTH
     *   <li>NOTZONE
     * <ul>
     *
     * @param string  $rcode  A DNS Packet RCODE name
     * @return integer The integer value of an RCODE
     */
    public static function rcodesbyname($rcode)
    {
        $rc = array(
                'NOERROR' => 0, // RFC 1035
                'FORMERR' => 1, // RFC 1035
                'SERVFAIL' => 2, // RFC 1035
                'NXDOMAIN' => 3, // RFC 1035
                'NOTIMP' => 4, // RFC 1035
                'REFUSED' => 5, // RFC 1035
                'YXDOMAIN' => 6, // RFC 2136
                'YXRRSET' => 7, // RFC 2136
                'NXRRSET' => 8, // RFC 2136
                'NOTAUTH' => 9, // RFC 2136
                'NOTZONE' => 10,  // RFC 2136
                );
        if (! strlen($rc[$rcode])) {
            $rc[$rcode] = null;
        }

        return $rc[$rcode];
    }

    /**
     * Translates rcode integers into names
     *
     * Translates the integer value of an rcode into it's name
     *
     * @param integer $rcodeval // A DNS packet rcode integer
     * @return string  // The name of the RCODE
     */
    public static function rcodesbyval($rcodeval)
    {
        $rc = array(
            0 => 'NOERROR',
            1 => 'FORMERR',
            2 => 'SERVFAIL',
            3 => 'NXDOMAIN',
            4 => 'NOTIMP',
            5 => 'REFUSED',
            6 => 'YXDOMAIN',
            7 => 'YXRRSET',
            8 => 'NXRRSET',
            9 => 'NOTAUTH',
            10 => 'NOTZONE',
        );
        if (! strlen($rc[$rcodeval])) {
            $rc[$rcodeval] = null;
        }

        return $rc[$rcodeval];
    }

    /**
     * Translates RR type names into integers
     *
     * Translates a Resource Record from it's name to it's  integer value.
     * Valid resource record types are:
     *
     * <ul>
     *   <li>A
     *   <li>NS
     *   <li>MD
     *   <li>MF
     *   <li>CNAME
     *   <li>SOA
     *   <li>MB
     *   <li>MG
     *   <li>MR
     *   <li>NULL
     *   <li>WKS
     *   <li>PTR
     *   <li>HINFO
     *   <li>MINFO
     *   <li>MX
     *   <li>TXT
     *   <li>RP
     *   <li>AFSDB
     *   <li>X25
     *   <li>ISDN
     *   <li>RT
     *   <li>NSAP
     *   <li>NSAP_PTR
     *   <li>SIG
     *   <li>KEY
     *   <li>PX
     *   <li>GPOS
     *   <li>AAAA
     *   <li>LOC
     *   <li>NXT
     *   <li>EID
     *   <li>NIMLOC
     *   <li>SRV
     *   <li>ATMA
     *   <li>NAPTR
     *   <li>TSIG
     *   <li>UINFO
     *   <li>UID
     *   <li>GID
     *   <li>UNSPEC
     *   <li>IXFR
     *   <li>AXFR
     *   <li>MAILB
     *   <li>MAILA
     *   <li>ANY
     * <ul>
     *
     * @param string $rrtype // A DNS packet RR type name
     * @return integer // The integer value of an RR type
     */
    public static function typesbyname($rrtype)
    {
        $rc = array(
            'A' => 1,
            'NS' => 2,
            'MD' => 3,
            'MF' => 4,
            'CNAME' => 5,
            'SOA' => 6,
            'MB' => 7,
            'MG' => 8,
            'MR' => 9,
            'NULL' => 10,
            'WKS' => 11,
            'PTR' => 12,
            'HINFO' => 13,
            'MINFO' => 14,
            'MX' => 15,
            'TXT' => 16,
            'RP' => 17,
            'AFSDB' => 18,
            'X25' => 19,
            'ISDN' => 20,
            'RT' => 21,
            'NSAP' => 22,
            'NSAP_PTR' => 23,
            'SIG' => 24,
            'KEY' => 25,
            'PX' => 26,
            'GPOS' => 27,
            'AAAA' => 28,
            'LOC' => 29,
            'NXT' => 30,
            'EID' => 31,
            'NIMLOC' => 32,
            'SRV' => 33,
            'ATMA' => 34,
            'NAPTR' => 35,
            'UINFO' => 100,
            'UID' => 101,
            'GID' => 102,
            'UNSPEC' => 103,
            'TSIG' => 250,
            'IXFR' => 251,
            'AXFR' => 252,
            'MAILB' => 253,
            'MAILA' => 254,
            'ANY' => 255,
        );
        if (empty($rc[$rrtype])) {
            $rc[$rrtype] = null;
        }

        return $rc[$rrtype];
    }

    /**
     * Translates RR type integers into names
     *
     * Translates the integer value of an RR type into it's name
     *
     * @param integer $rrtypeval // A DNS packet RR type integer
     * @return string // The name of the RR type
     */
    public static function typesbyval($rrtypeval)
    {
        $rc = array(
            1 => 'A',
            2 => 'NS',
            3 => 'MD',
            4 => 'MF',
            5 => 'CNAME',
            6 => 'SOA',
            7 => 'MB',
            8 => 'MG',
            9 => 'MR',
            10 => 'NULL',
            11 => 'WKS',
            12 => 'PTR',
            13 => 'HINFO',
            14 => 'MINFO',
            15 => 'MX',
            16 => 'TXT',
            17 => 'RP',
            18 => 'AFSDB',
            19 => 'X25',
            20 => 'ISDN',
            21 => 'RT',
            22 => 'NSAP',
            23 => 'NSAP_PTR',
            24 => 'SIG',
            25 => 'KEY',
            26 => 'PX',
            27 => 'GPOS',
            28 => 'AAAA',
            29 => 'LOC',
            30 => 'NXT',
            31 => 'EID',
            32 => 'NIMLOC',
            33 => 'SRV',
            34 => 'ATMA',
            35 => 'NAPTR',
            100 => 'UINFO',
            101 => 'UID',
            102 => 'GID',
            103 => 'UNSPEC',
            250 => 'TSIG',
            251 => 'IXFR',
            252 => 'AXFR',
            253 => 'MAILB',
            254 => 'MAILA',
            255 => 'ANY',
        );
        $rrtypeval = preg_replace(array('/\s*/',' /^0*/'), '', $rrtypeval);
        if (empty($rc[$rrtypeval])) {
            $rc[$rrtypeval] = null;
        }

        return $rc[$rrtypeval];
    }

    /**
     * translates a DNS class from it's name to it's  integer value. Valid
     * class names are:
     * <ul>
     *   <li>IN
     *   <li>CH
     *   <li>HS
     *   <li>NONE
     *   <li>ANY
     * </ul>
     *
     * @param   string  $class // A DNS packet class type
     * @return  integer // The integer value of an class type
     */
    public function classesbyname($class)
    {
        $rc = array(
            'IN'   => 1, // RFC 1035
            'CH'   => 3, // RFC 1035
            'HS'   => 4, // RFC 1035
            'NONE' => 254, // RFC 2136
            'ANY'  => 255, // RFC 1035
        );
        if (!isset($rc[$class])) {
            $rc[$class] = null;
        }

        return $rc[$class];
    }

    /**
     * Translates RR class integers into names
     *
     * Translates the integer value of an RR class into it's name
     *
     * @param   integer $classval // A DNS packet RR class integer
     * @return  string // The name of the RR class
     */
    public static function classesbyval($classval)
    {
        $rc = array(
            1 => 'IN',
            3 => 'CH',
            4 => 'HS',
            254 => 'NONE',
            255 => 'ANY',
        );
        $classval = preg_replace(array('/\s*/',' /^0*/'), '', $classval);
        if (empty($rc[$classval])) {
            $rc[$classval] = null;
        }

        return $rc[$classval];
    }
}
