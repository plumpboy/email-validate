<?php

/**
 * Object representation of the HEADER section of a DNS packet
 *
 * The DNS::Header class contains the values of a DNS  packet. It parses
 * the header of a DNS packet or can generate the binary data
 * representation of the packet. The format of the header is described in
 * RFC1035.
 *
 */

namespace Plumpboy\EmailValidate\Net\DNS;

use Plumpboy\EmailValidate\Net\DNS;
use Plumpboy\EmailValidate\Net\DNS\Resolver;

class Header
{
    /**
     * The packet's request id
     *
     * The request id of the packet represented as  a 16 bit integer.
     */
    protected $id;
    /**
     * The QR bit in a DNS packet header
     *
     * The QR bit as described in RFC1035. QR is set to 0 for queries, and
     * 1 for repsones.
     */
    protected $qr;
    /**
     * The OPCODE name of this packet.
     *
     * The string value (name) of the opcode for the DNS packet.
     */
    protected $opcode;
    /**
     * The AA (authoritative answer) bit in a DNS packet header
     *
     * The AA bit as described in RFC1035.  AA is set to  1 if the answer
     * is authoritative.  It has no meaning if QR is set to 0.
     */
    protected $aa;
    /**
     * The TC (truncated) bit in a DNS packet header
     *
     * This flag is set to 1 if the response was truncated.  This flag has
     * no meaning in a query packet.
     */
    protected $tc;
    /**
     * The RD (recursion desired) bit in a DNS packet header
     *
     * This bit should be set to 1 in a query if recursion  is desired by
     * the DNS server.
     */
    protected $rd;
    /**
     * The RA (recursion available) bit in a DNS packet header
     *
     * This bit is set to 1 by the DNS server if the server is willing to
     * perform recursion.
     */
    protected $ra;
    /**
     * The RCODE name for this packet.
     *
     * The string value (name) of the rcode for the DNS packet.
     */
    protected $rcode;
    /**
     * Number of questions contained within the packet
     *
     * 16bit integer representing the number of questions in the question
     * section of the DNS packet.
     *
     * @var integer $qdcount
     * @see Question class
     */
    protected $qdcount;
    /**
     * Number of answer RRs contained within the packet
     *
     * 16bit integer representing the number of answer resource records
     * contained in the answer section of the DNS packet.
     *
     * @var integer $ancount
     */
    protected $ancount;
    /**
     * Number of authority RRs within the packet
     *
     * 16bit integer representing the number of authority (NS) resource
     * records  contained in the authority section of the DNS packet.
     *
     * @var integer $nscount
     */
    protected $nscount;
    /**
     * Number of additional RRs within the packet
     *
     * 16bit integer representing the number of additional resource records
     * contained in the additional section of the DNS packet.
     *
     * @var integer $arcount
     */
    protected $arcount;

    /**
     * Initializes the default values for the Header object.
     *
     * Builds a header object from either default values, or from a DNS
     * packet passed into the constructor as $data
     *
     * @param string $data // A DNS packet of which the header will be parsed.
     */
    public function __construct($data = '')
    {
        if ($data != '') {
            /*
             * The header MUST be at least 12 bytes.
             * Passing the full datagram to this constructor
             * will examine only the header section of the DNS packet
             */
            if (strlen($data) < 12) {
                return false;
            }

            $a = unpack('nid/C2flags/n4counts', $data);
            $this->id = $a['id'];
            $this->qr = ($a['flags1'] >> 7) & 0x1;
            $this->opcode = ($a['flags1'] >> 3) & 0xf;
            $this->aa = ($a['flags1'] >> 2) & 0x1;
            $this->tc = ($a['flags1'] >> 1) & 0x1;
            $this->rd = $a['flags1'] & 0x1;
            $this->ra = ($a['flags2'] >> 7) & 0x1;
            $this->rcode = $a['flags2'] & 0xf;
            $this->qdcount = $a['counts1'];
            $this->ancount = $a['counts2'];
            $this->nscount = $a['counts3'];
            $this->arcount = $a['counts4'];
        } else {
            $this->id = Resolver::nextid();
            $this->qr = 0;
            $this->opcode = 0;
            $this->aa = 0;
            $this->tc = 0;
            $this->rd = 1;
            $this->ra = 0;
            $this->rcode = 0;
            $this->qdcount = 1;
            $this->ancount = 0;
            $this->nscount = 0;
            $this->arcount = 0;
        }

        if (DNS::opcodesbyval($this->opcode)) {
            $this->opcode = DNS::opcodesbyval($this->opcode);
        }
        if (DNS::rcodesbyval($this->rcode)) {
            $this->rcode = DNS::rcodesbyval($this->rcode);
        }
    }

    /**
     * Displays the properties of the header.
     *
     * Displays the properties of the header.
     */
    public function display()
    {
        echo $this->string();
    }

    /**
     * Returns a formatted string containing the properties of the header.
     *
     * @return string // A formatted string containing the properties of the header.
     */
    public function string()
    {
        $retval = ';; id = ' . $this->id . "\n";
        if ($this->opcode == 'UPDATE') {
            $retval .= ';; qr = ' . $this->qr . '    ' .
                'opcode = ' . $this->opcode . '    ' .
                'rcode = ' . $this->rcode . "\n";
            $retval .= ';; zocount = ' . $this->qdcount . '  ' .
                'prcount = ' . $this->ancount . '  ' .
                'upcount = ' . $this->nscount . '  ' .
                'adcount = ' . $this->arcount . "\n";
        } else {
            $retval .= ';; qr = ' . $this->qr . '    ' .
                'opcode = ' . $this->opcode . '    ' .
                'aa = ' . $this->aa . '    ' .
                'tc = ' . $this->tc . '    ' .
                'rd = ' . $this->rd . "\n";

            $retval .= ';; ra = ' . $this->ra . '    ' .
                'rcode  = ' . $this->rcode . "\n";

            $retval .= ';; qdcount = ' . $this->qdcount . '  ' .
                'ancount = ' . $this->ancount . '  ' .
                'nscount = ' . $this->nscount . '  ' .
                'arcount = ' . $this->arcount . "\n";
        }

        return $retval;
    }

    /**
     * Returns the binary data containing the properties of the header
     *
     * Packs the properties of the Header object into a binary string
     * suitable for using as the Header section of a DNS packet.
     *
     * @return string // Binary representation of the header object
     */
    public function data()
    {
        $opcode = DNS::opcodesbyname($this->opcode);
        $rcode  = DNS::rcodesbyname($this->rcode);

        $byte2 = ($this->qr << 7)
            | ($opcode << 3)
            | ($this->aa << 2)
            | ($this->tc << 1)
            | ($this->rd);

        $byte3 = ($this->ra << 7) | $rcode;

        return pack(
            'nC2n4',
            $this->id,
            $byte2,
            $byte3,
            $this->qdcount,
            $this->ancount,
            $this->nscount,
            $this->arcount
        );
    }
}
