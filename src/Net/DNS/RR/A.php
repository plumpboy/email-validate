<?php

/**
 * A representation of a resource record of type <A>
 *
 */

namespace Plumpboy\EmailValidate\Net\DNS\RR;

use Plumpboy\EmailValidate\Net\DNS\RR;

class A extends RR
{
    protected $name;
    protected $type;
    protected $class;
    protected $ttl;
    protected $rdlength;
    protected $rdata;
    protected $address;

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
                /*
                 *  We don't have inet_ntoa in PHP?
                 */
                $aparts = unpack('C4b', $this->rdata);
                $addr = $aparts['b1'] . '.' .
                    $aparts['b2'] . '.' .
                    $aparts['b3'] . '.' .
                    $aparts['b4'];
                $this->address = $addr;
            }
        } else {
            if (strlen($data) && ereg("([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)[ \t]*$", $data, $regs)) {
                if (
                        ($regs[1] >= 0 && $regs[1] <= 255) &&
                        ($regs[2] >= 0 && $regs[2] <= 255) &&
                        ($regs[3] >= 0 && $regs[3] <= 255) &&
                        ($regs[4] >= 0 && $regs[4] <= 255)
                ) {
                    $this->address = $regs[1] . '.' . $regs[2] . '.' . $regs[3] . '.' .$regs[4];
                }
            }
        }
    }

    public function rdatastr()
    {
        if (strlen($this->address)) {
            return $this->address;
        }

        return '; no data';
    }

    public function rr_rdata($packet, $offset)
    {
        $aparts = split('\.', $this->address);
        if (count($aparts) == 4) {
            return pack('c4', $aparts[0], $aparts[1], $aparts[2], $aparts[3]);
        }

        return null;
    }
}
