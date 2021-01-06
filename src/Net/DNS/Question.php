<?php

/**
 * Builds or parses the QUESTION section of a DNS packet
 *
 * Builds or parses the QUESTION section of a DNS packet
 *
 */

namespace Plumpboy\EmailValidate\Net\DNS;

use Plumpboy\EmailValidate\Net\DNS;
use Plumpboy\EmailValidate\Net\DNS\RR;
use Plumpboy\EmailValidate\Net\DNS\Header;

class Question
{
    public $qname = null;
    public $qtype = null;
    public $qclass = null;

    /**
     *  Initalizes a DNS\Packet object
     * @param [type] $qname  [description]
     * @param [type] $qtype  [description]
     * @param [type] $qclass [description]
     */
    public function __construct($qname, $qtype, $qclass)
    {
        $qtype = !is_null($qtype) ? strtoupper($qtype)  : 'ANY';
        $qclass = !is_null($qclass) ? strtoupper($qclass) : 'ANY';

        // Check if the caller has the type and class reversed.
        // We are not that kind for unknown types.... :-)
        if ((is_null(DNS::typesbyname($qtype)) || is_null(DNS::classesbyname($qtype)))
          && !is_null(DNS::classesbyname($qclass))
          && !is_null(DNS::typesbyname($qclass)))
        {
            list($qtype, $qclass) = array($qclass, $qtype);
        }
        $qname = preg_replace(array('/^\.+/', '/\.+$/'), '', $qname);
        $this->qname = $qname;
        $this->qtype = $qtype;
        $this->qclass = $qclass;
    }

    function display()
    {
        echo $this->string() . "\n";
    }

    function string()
    {
        return $this->qname . ".\t" . $this->qclass . "\t" . $this->qtype;
    }

    function data($packet, $offset)
    {
        $data = $packet->dn_comp($this->qname, $offset);
        $data .= pack('n', Net_DNS::typesbyname(strtoupper($this->qtype)));
        $data .= pack('n', Net_DNS::classesbyname(strtoupper($this->qclass)));

        return $data;
    }
}
