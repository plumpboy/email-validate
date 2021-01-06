<?php

/**
 * A representation of a resource record of type <MX>
 */

namespace Plumpboy\EmailValidate\Net\DNS\RR;

use Plumpboy\EmailValidate\Net\DNS\RR;
use Plumpboy\EmailValidate\Net\DNS\Packet;

class MX extends RR
{
    protected $name;
    protected $type;
    protected $class;
    protected $ttl;
    protected $rdlength;
    protected $rdata;
    protected $preference;
    protected $exchange;

    public function __construct(&$rro, $data, $offset = '')
    {
        $this->name = $rro->name;
        $this->type = $rro->type;
        $this->class = $rro->class;
        $this->ttl = $rro->ttl;
        $this->rdlength = $rro->rdlength;
        $this->rdata = $rro->rdata;

        if ($offset) {
            if ($this->rdlength > 0) {
                $a = unpack("@$offset/npreference", $data);
                $offset += 2;
                list($exchange, $offset) = Packet::dn_expand($data, $offset);
                $this->preference = $a['preference'];
                $this->exchange = $exchange;
            }
        } else {
            ereg("([0-9]+)[ \t]+(.+)[ \t]*$", $data, $regs);
            $this->preference = $regs[1];
            $this->exchange = ereg_replace('(.*)\.$', '\\1', $regs[2]);
        }
    }

    public function rdatastr()
    {
        if (preg_match('/^[0-9]+$/', $this->preference)) {
            return $this->preference . ' ' . $this->exchange . '.';
        }

        return '; no data';
    }

    public function rr_rdata($packet, $offset)
    {
        if (preg_match('/^[0-9]+$/', $this->preference)) {
            $rdata = pack('n', $this->preference);
            $rdata .= $packet->dn_comp($this->exchange, $offset + strlen($rdata));

            return $rdata;
        }

        return null;
    }
}
