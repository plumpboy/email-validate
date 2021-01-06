<?php

/**
 * A representation of a resource record of type <SOA>
 */

namespace Plumpboy\EmailValidate\Net\DNS\RR;

use Plumpboy\EmailValidate\Net\DNS\RR;
use Plumpboy\EmailValidate\Net\DNS\Packet;

class SOA extends RR
{
    protected $name;
    protected $type;
    protected $class;
    protected $ttl;
    protected $rdlength;
    protected $rdata;
    protected $mname;
    protected $rname;
    protected $serial;
    protected $refresh;
    protected $retry;
    protected $expire;
    protected $minimum;

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
                list($mname, $offset) = Packet::dn_expand($data, $offset);
                list($rname, $offset) = Packet::dn_expand($data, $offset);

                $a = unpack("@$offset/N5soavals", $data);
                $this->mname = $mname;
                $this->rname = $rname;
                $this->serial = $a['soavals1'];
                $this->refresh = $a['soavals2'];
                $this->retry = $a['soavals3'];
                $this->expire = $a['soavals4'];
                $this->minimum = $a['soavals5'];
            }
        } else {
            if (ereg("([^ \t]+)[ \t]+([^ \t]+)[ \t]+([0-9]+)[^ \t]+([0-9]+)[^ \t]+([0-9]+)[^ \t]+([0-9]+)[^ \t]*$", $string, $regs)) {
                $this->mname = ereg_replace('(.*)\.$', '\\1', $regs[1]);
                $this->rname = ereg_replace('(.*)\.$', '\\1', $regs[2]);
                $this->serial = $regs[3];
                $this->refresh = $regs[4];
                $this->retry = $regs[5];
                $this->expire = $regs[6];
                $this->minimum = $regs[7];
            }
        }
    }

    public function rdatastr($pretty = 0)
    {
        if (strlen($this->mname)) {
            if ($pretty) {
                $rdatastr  = $this->mname . '. ' . $this->rname . ". (\n";
                $rdatastr .= "\t\t\t\t\t" . $this->serial . "\t; Serial\n";
                $rdatastr .= "\t\t\t\t\t" . $this->refresh . "\t; Refresh\n";
                $rdatastr .= "\t\t\t\t\t" . $this->retry . "\t; Retry\n";
                $rdatastr .= "\t\t\t\t\t" . $this->expire . "\t; Expire\n";
                $rdatastr .= "\t\t\t\t\t" . $this->minimum . " )\t; Minimum TTL";
            } else {
                $rdatastr  = $this->mname . '. ' . $this->rname . '. ' .
                    $this->serial . ' ' .  $this->refresh . ' ' .  $this->retry . ' ' .
                    $this->expire . ' ' .  $this->minimum;
            }

            return $rdatastr;
        }

        return '; no data';
    }

    public function rr_rdata($packet, $offset)
    {
        if (strlen($this->mname)) {
            $rdata = $packet->dn_comp($this->mname, $offset);
            $rdata .= $packet->dn_comp($this->rname, $offset + strlen($rdata));
            $rdata .= pack(
                'N5',
                $this->serial,
                $this->refresh,
                $this->retry,
                $this->expire,
                $this->minimum
            );

            return $rdata;
        }

        return null;
    }
}
