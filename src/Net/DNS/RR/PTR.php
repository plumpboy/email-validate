<?php

/**
 * A representation of a resource record of type <PTR>
 */

namespace Plumpboy\EmailValidate\Net\DNS\RR;

use Plumpboy\EmailValidate\Net\DNS\RR;
use Plumpboy\EmailValidate\Net\DNS\Packet;

class PTR extends RR
{
    protected $name;
    protected $type;
    protected $class;
    protected $ttl;
    protected $rdlength;
    protected $rdata;
    protected $ptrdname;

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
                list($ptrdname, $offset) = Packet::dn_expand($data, $offset);
                $this->ptrdname = $ptrdname;
            }
        } else {
            $this->ptrdname = ereg_replace("[ \t]+(.+)[ \t]*$", '\\1', $data);
        }
    }

    public function rdatastr()
    {
        if (strlen($this->ptrdname)) {
            return $this->ptrdname . '.';
        }

        return '; no data';
    }

    public function rr_rdata($packet, $offset)
    {
        if (strlen($this->ptrdname)) {
            return $packet->dn_comp($this->ptrdname, $offset);
        }

        return null;
    }
}
