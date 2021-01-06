<?php

/**
 * A representation of a resource record of type <HINFO>
 */

namespace Plumpboy\EmailValidate\Net\DNS\RR;

use Plumpboy\EmailValidate\Net\DNS\RR;
use Plumpboy\EmailValidate\Net\DNS\Packet;

class HINFO extends RR
{
    protected $name;
    protected $type;
    protected $class;
    protected $ttl;
    protected $rdlength;
    protected $rdata;
    protected $cpu;
    protected $os;

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
                list($cpu, $offset) = Packet::label_extract($data, $offset);
                list($os, $offset) = Packet::label_extract($data, $offset);

                $this->cpu = $cpu;
                $this->os  = $os;
            }
        } else {
            $data = str_replace('\\\\', chr(1) . chr(1), $data); /* disguise escaped backslash */
            $data = str_replace('\\"', chr(2) . chr(2), $data); /* disguise \" */

            ereg('("[^"]*"|[^ \t]*)[ \t]+("[^"]*"|[^ \t]*)[ \t]*$', $data, $regs);
            foreach ($regs as $idx => $value) {
                $value = str_replace(chr(2) . chr(2), '\\"', $value);
                $value = str_replace(chr(1) . chr(1), '\\\\', $value);
                $regs[$idx] = stripslashes($value);
            }

            $this->cpu = $regs[1];
            $this->os = $regs[2];
        }
    }

    public function rdatastr()
    {
        if ($this->text) {
            return '"' . addslashes($this->cpu) . '" "' . addslashes($this->os) . '"';
        }

        return '; no data';
    }

    public function rr_rdata($packet, $offset)
    {
        if ($this->text) {
            $rdata  = pack('C', strlen($this->cpu)) . $this->cpu;
            $rdata .= pack('C', strlen($this->os))  . $this->os;

            return $rdata;
        }

        return null;
    }
}
