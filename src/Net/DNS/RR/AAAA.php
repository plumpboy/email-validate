<?php

/**
 * A representation of a resource record of type <AAAA>
 *
 */

namespace Plumpboy\EmailValidate\Net\DNS\RR;

use Plumpboy\EmailValidate\Net\DNS\RR;

class AAAA extends RR
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
            $this->address = self::ipv6_decompress(substr($this->rdata, 0, $this->rdlength));
        } else {
            if (strlen($data)) {
                if (count($adata = explode(':', $data, 8)) >= 3) {
                    foreach ($adata as $addr) {
                        if (!preg_match('/^[0-9A-F]{0,4}$/i', $addr)) {
                            return;
                        }
                    }
                    $this->address = trim($data);
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
        return self::ipv6_compress($this->address);
    }

    public static function ipv6_compress($addr)
    {
        $numparts = count(explode(':', $addr));
        if ($numparts < 3 || $numparts > 8 ||
            !preg_match('/^([0-9A-F]{0,4}:){0,7}(:[0-9A-F]{0,4}){0,7}$/i', $addr)) {
            /* Non-sensical IPv6 address */
            return pack('n8', 0, 0, 0, 0, 0, 0, 0, 0);
        }
        if (strpos($addr, '::') !== false) {
            /* First we have to normalize the address, turn :: into :0:0:0:0: */
            $filler = str_repeat(':0', 9 - $numparts) . ':';
            if (substr($addr, 0, 2) == '::') {
                $filler = "0$filler";
            }
            if (substr($addr, -2, 2) == '::') {
                $filler .= '0';
            }
            $addr = str_replace('::', $filler, $addr);
        }
        $aparts = explode(':', $addr);

        return pack(
            'n8',
            hexdec($aparts[0]),
            hexdec($aparts[1]),
            hexdec($aparts[2]),
            hexdec($aparts[3]),
            hexdec($aparts[4]),
            hexdec($aparts[5]),
            hexdec($aparts[6]),
            hexdec($aparts[7])
        );
    }

    public static function ipv6_decompress($pack)
    {
        if (strlen($pack) != 16) {
            /* Must be 8 shorts long */
            return '::';
        }
        $a = unpack('n8', $pack);
        $addr = vsprintf("%x:%x:%x:%x:%x:%x:%x:%x", $a);
        /* Shorthand the first :0:0: set into a :: */
        /* TODO: Make this is a single replacement pattern */
        if (substr($addr, -4) == ':0:0') {
            return preg_replace('/((:0){2,})$/', '::', $addr);
        } elseif (substr($addr, 0, 4) == '0:0:') {
            return '0:0:'. substr($addr, 4);
        } else {
            return preg_replace('/(:(0:){2,})/', '::', $addr);
        }
    }
}
