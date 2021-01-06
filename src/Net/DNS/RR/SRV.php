<?php

/**
 * A representation of a resource record of type <SRV>
 */

namespace Plumpboy\EmailValidate\Net\DNS\RR;

use Plumpboy\EmailValidate\Net\DNS\RR;
use Plumpboy\EmailValidate\Net\DNS\Packet;

class SRV extends RR
{
    protected $name;
    protected $type;
    protected $class;
    protected $ttl;
    protected $rdlength;
    protected $rdata;
    protected $preference;
    protected $weight;
    protected $port;
    protected $target;

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
                $a = unpack("@$offset/npreference/nweight/nport", $data);
                $offset += 6;
                list($target, $offset) = Packet::dn_expand($data, $offset);
                $this->preference = $a['preference'];
                $this->weight = $a['weight'];
                $this->port = $a['port'];
                $this->target = $target;
            }
        } else {
            ereg("([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+(.+)[ \t]*$", $data, $regs);
            $this->preference = $regs[1];
            $this->weight = $regs[2];
            $this->port = $regs[3];
            $this->target = ereg_replace('(.*)\.$', '\\1', $regs[4]);
        }
    }

    public function rdatastr()
    {
        if ($this->port) {
            return intval($this->preference) . ' ' . intval($this->weight) . ' ' . intval($this->port) . ' ' . $this->target . '.';
        }

        return '; no data';
    }

    public function rr_rdata($packet, $offset)
    {
        if (isset($this->preference)) {
            $rdata = pack('nnn', $this->preference, $this->weight, $this->port);
            $rdata .= $packet->dn_comp($this->target, $offset + strlen($rdata));

            return $rdata;
        }

        return null;
    }
}
