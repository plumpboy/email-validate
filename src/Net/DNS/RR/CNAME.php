<?php

/**
 * A representation of a resource record of type <CNAME>
 */

namespace Plumpboy\EmailValidate\Net\DNS\RR;

use Plumpboy\EmailValidate\Net\DNS\RR;
use Plumpboy\EmailValidate\Net\DNS\Packet;

class CNAME extends RR
{
    protected $name;
    protected $type;
    protected $class;
    protected $ttl;
    protected $rdlength;
    protected $rdata;
    protected $cname;

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
                list($cname, $offset) = Packet::dn_expand($data, $offset);
                $this->cname = $cname;
            }
        } else {
            $this->cname = ereg_replace("[ \t]+(.+)[\. \t]*$", '\\1', $data);
        }
    }

    public function rdatastr()
    {
        if (strlen($this->cname)) {
            return $this->cname . '.';
        }

        return '; no data';
    }

    public function rr_rdata($packet, $offset)
    {
        if (strlen($this->cname)) {
            return $packet->dn_comp($this->cname, $offset);
        }

        return null;
    }
}
