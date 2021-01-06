<?php

namespace Plumpboy\EmailValidate\Net\DNS;

use Plumpboy\EmailValidate\Net\DNS\RR\A;
use Plumpboy\EmailValidate\Net\DNS\RR\AAAA;
use Plumpboy\EmailValidate\Net\DNS\RR\NS;
use Plumpboy\EmailValidate\Net\DNS\RR\CNAME;
use Plumpboy\EmailValidate\Net\DNS\RR\PTR;
use Plumpboy\EmailValidate\Net\DNS\RR\SOA;
use Plumpboy\EmailValidate\Net\DNS\RR\MX;
use Plumpboy\EmailValidate\Net\DNS\RR\TSIG;
use Plumpboy\EmailValidate\Net\DNS\RR\TXT;
use Plumpboy\EmailValidate\Net\DNS\RR\HINFO;
use Plumpboy\EmailValidate\Net\DNS\RR\SRV;
use Plumpboy\EmailValidate\Net\DNS\RR\NAPTR;

/**
 * Resource Record object definition
 *
 * Builds or parses resource record sections of the DNS packet including
 * the answer, authority, and additional sections of the packet.
 *
 */
class RR
{
    private $name;
    private $type;
    private $class;
    private $ttl;
    private $rdlength;
    private $rdata;

    /*
     * Use DNS\RR::factory() instead
     */
    public function __construct($rrdata)
    {
        if ($rrdata != 'getRR') { // BC check/warning remove later
            trigger_error("Please use DNS\RR::factory() instead");
        }
    }

    /**
     * Returns an RR object, use this instead of constructor
     *
     * @param mixed $rr_rdata [Options as string, array or data]
     *
     * @return object [DNS\RR or DNS\RR\<type>]
     */
    public function &factory($rrdata, $update_type = '')
    {
        if (is_string($rrdata)) {
            $rr = &static::new_from_string($rrdata, $update_type);
        } elseif (count($rrdata) == 7) {
            list($name, $rrtype, $rrclass, $ttl, $rdlength, $data, $offset) = $rrdata;
            $rr = &static::new_from_data($name, $rrtype, $rrclass, $ttl, $rdlength, $data, $offset);
        } else {
            $rr = &static::new_from_array($rrdata);
        }

        return $rr;
    }

    public static function &new_from_data($name, $rrtype, $rrclass, $ttl, $rdlength, $data, $offset)
    {
        $rr = &new RR('getRR');
        $rr->name = $name;
        $rr->type = $rrtype;
        $rr->class = $rrclass;
        $rr->ttl = $ttl;
        $rr->rdlength = $rdlength;
        $rr->rdata = substr($data, $offset, $rdlength);
        if (class_exists(constant("$rrtype::class"))) {
            $scn = constant("$rrtype::class");

            $rr = new $scn($rr, $data, $offset);
        }

        return $rr;
    }

    public static function &new_from_string($rrstring, $update_type = '')
    {
        $rr = &new RR('getRR');
        $ttl = 0;
        $parts = preg_split('/[\s]+/', $rrstring);
        while (count($parts) > 0) {
			$s = array_shift($parts);
            if (!isset($name)) {
                $name = ereg_replace('\.+$', '', $s);
            } else if (preg_match('/^\d+$/', $s)) {
                $ttl = $s;
            } else if (!isset($rrclass) && ! is_null(DNS::classesbyname(strtoupper($s)))) {
                $rrclass = strtoupper($s);
                $rdata = join(' ', $parts);
            } else if (! is_null(DNS::typesbyname(strtoupper($s)))) {
                $rrtype = strtoupper($s);
                $rdata = join(' ', $parts);
                break;
            } else {
                break;
            }
        }

        /*
         *  Do we need to do this?
         */
        $rdata = trim(chop($rdata));

        if (! strlen($rrtype) && strlen($rrclass) && $rrclass == 'ANY') {
            $rrtype = $rrclass;
            $rrclass = 'IN';
        } else if (! isset($rrclass)) {
            $rrclass = 'IN';
        }

        if (! strlen($rrtype)) {
            $rrtype = 'ANY';
        }

        if (strlen($update_type)) {
            $update_type = strtolower($update_type);
            if ($update_type == 'yxrrset') {
                $ttl = 0;
                if (! strlen($rdata)) {
                    $rrclass = 'ANY';
                }
            } else if ($update_type == 'nxrrset') {
                $ttl = 0;
                $rrclass = 'NONE';
                $rdata = '';
            } else if ($update_type == 'yxdomain') {
                $ttl = 0;
                $rrclass = 'ANY';
                $rrtype = 'ANY';
                $rdata = '';
            } else if ($update_type == 'nxdomain') {
                $ttl = 0;
                $rrclass = 'NONE';
                $rrtype = 'ANY';
                $rdata = '';
            } else if (preg_match('/^(rr_)?add$/', $update_type)) {
                $update_type = 'add';
                if (! $ttl) {
                    $ttl = 86400;
                }
            } else if (preg_match('/^(rr_)?del(ete)?$/', $update_type)) {
                $update_type = 'del';
                $ttl = 0;
                $rrclass = $rdata ? 'NONE' : 'ANY';
            }
        }

        if (strlen($rrtype)) {
            $rr->name = $name;
            $rr->type = $rrtype;
            $rr->class = $rrclass;
            $rr->ttl = $ttl;
            $rr->rdlength = 0;
            $rr->rdata = '';

            if (class_exists(constant("$rrtype::class"))) {
                $scn = constant("$rrtype::class");

                return new $scn($rr, $rdata);
            } else {
                return $rr;
            }
        } else {
            return null;
        }
    }

    public static function &new_from_array($rrarray)
    {
        $rr = &new RR('getRR');
        foreach ($rrarray as $k => $v) {
            $rr->{strtolower($k)} = $v;
        }

        if (! strlen($rr->name)) {
            return null;
        }
        if (! strlen($rr->type)){
            return null;
        }
        if (! $rr->ttl) {
            $rr->ttl = 0;
        }
        if (! strlen($rr->class)) {
            $rr->class = 'IN';
        }
        if (strlen($rr->rdata)) {
            $rr->rdlength = strlen($rr->rdata);
        }
        if (class_exists(constant("$rrtype::class"))) {
            $scn = constant("$rrtype::class");

            return new $scn($rr, $rr->rdata);
        } else {
            return $rr;
        }
    }

    public function display()
    {
        echo $this->string() . "\n";
    }

    public function string()
    {
        return $this->name . ".\t" . (strlen($this->name) < 16 ? "\t" : '') .
            $this->ttl  . "\t"  .
            $this->class. "\t"  .
            $this->type . "\t"  .
            $this->rdatastr();
    }

    public function rdatastr()
    {
        if ($this->rdlength) {
            return '; rdlength = ' . $this->rdlength;
        }

        return '; no data';
    }

    public function rdata(&$packetORrdata, $offset = '')
    {
        if ($offset) {
            return $this->rr_rdata($packetORrdata, $offset);
        } else if (strlen($this->rdata)) {
            return $this->rdata;
        } else {
            return null;
        }
    }

    public function rr_rdata(&$packet, $offset)
    {
        return (strlen($this->rdata) ? $this->rdata : '');
    }

    public function data(&$packet, $offset)
    {
        $data = $packet->dn_comp($this->name, $offset);
        $data .= pack('n', DNS::typesbyname(strtoupper($this->type)));
        $data .= pack('n', DNS::classesbyname(strtoupper($this->class)));
        $data .= pack('N', $this->ttl);

        $offset += strlen($data) + 2; // The 2 extra bytes are for rdlength

        $rdata = $this->rdata($packet, $offset);
        $data .= pack('n', strlen($rdata));
        $data .= $rdata;

        return $data;
    }
}
