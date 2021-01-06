<?php

/**
 * A representation of a resource record of type <NS>
 */

namespace Plumpboy\EmailValidate\Net\DNS\RR;

use Plumpboy\EmailValidate\Net\DNS\RR;
use Plumpboy\EmailValidate\Net\DNS\Packet;

class NS extends RR
{
    protected $name;
    protected $type;
    protected $class;
    protected $ttl;
    protected $rdlength;
    protected $rdata;
    protected $nsdname;

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
                list($nsdname, $offset) = Packet::dn_expand($data, $offset);
                $this->nsdname = $nsdname;
            }
        } else {
            $this->nsdname = ereg_replace("[ \t]+(.+)[ \t]*$", '\\1', $data);
        }
    }

    public function rdatastr()
    {
        if (strlen($this->nsdname)) {
            return $this->nsdname . '.';
        }

        return '; no data';
    }

    public function rr_rdata($packet, $offset)
    {
        if (strlen($this->nsdname)) {
            return $packet->dn_comp($this->nsdname, $offset);
        }

        return null;
    }
}
