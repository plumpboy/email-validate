<?php

/**
 * A representation of a resource record of type <TSIG>
 */

namespace Plumpboy\EmailValidate\Net\DNS\RR;

use Plumpboy\EmailValidate\Net\DNS;
use Plumpboy\EmailValidate\Net\DNS\RR;
use Plumpboy\EmailValidate\Net\DNS\Packet;

class TSIG extends RR
{
    protected const NET_DNS_DEFAULT_ALGORITHM = 'hmac-md5.sig-alg.reg.int';
    protected const NET_DNS_DEFAULT_FUDGE = 300;
    protected $name;
    protected $type;
    protected $class;
    protected $ttl;
    protected $rdlength;
    protected $rdata;
    protected $time_signed;
    protected $fudge;
    protected $mac_size;
    protected $mac;
    protected $original_id;
    protected $error;
    protected $other_len;
    protected $other_data;
    protected $key;

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
                list($alg, $offset) = Packet::dn_expand($data, $offset);
                $this->algorithm = $alg;

                $d = unpack("\@$offset/nth/Ntl/nfudge/nmac_size", $data);
                $time_high = $d['th'];
                $time_low = $d['tl'];
                $this->time_signed = $time_low;
                $this->fudge = $d['fudge'];
                $this->mac_size = $d['mac_size'];
                $offset += 10;

                $this->mac = substr($data, $offset, $this->mac_size);
                $offset += $this->mac_size;

                $d = unpack("@$offset/noid/nerror/nolen", $data);
                $this->original_id = $d['oid'];
                $this->error = $d['error'];
                $this->other_len = $d['olen'];
                $offset += 6;

                $odata = substr($data, $offset, $this->other_len);
                $d = unpack('nodata_high/Nodata_low', $odata);
                $this->other_data = $d['odata_low'];
            }
        } else {
            if (strlen($data) && preg_match('/^(.*)$/', $data, $regs)) {
                $this->key = $regs[1];
            }

            $this->algorithm = self::NET_DNS_DEFAULT_ALGORITHM;
            $this->time_signed = time();

            $this->fudge = self::NET_DNS_DEFAULT_FUDGE;
            $this->mac_size = 0;
            $this->mac = '';
            $this->original_id = 0;
            $this->error = 0;
            $this->other_len = 0;
            $this->other_data = '';

            // RFC 2845 Section 2.3
            $this->class = 'ANY';
        }
    }

    public function rdatastr()
    {
        $error = $this->error;
        if (! $error) {
            $error = 'UNDEFINED';
        }

        if (strlen($this->algorithm)) {
            $rdatastr = $this->algorithm . '. ' . $this->time_signed . ' ' .
                $this->fudge . ' ';
            if ($this->mac_size && strlen($this->mac)) {
                $rdatastr .= ' ' . $this->mac_size . ' ' . base64_encode($this->mac);
            } else {
                $rdatastr .= ' 0 ';
            }
            $rdatastr .= ' ' . $this->original_id . ' ' . $error;
            if ($this->other_len && strlen($this->other_data)) {
                $rdatastr .= ' ' . $this->other_data;
            } else {
                $rdatastr .= ' 0 ';
            }
        } else {
            $rdatastr = '; no data';
        }

        return $rdatastr;
    }

    public function rr_rdata($packet, $offset)
    {
        $rdata = '';
        $sigdata = '';

        if (strlen($this->key)) {
            $key = $this->key;
            $key = ereg_replace(' ', '', $key);
            $key = base64_decode($key);

            $newpacket = $packet;
            $newoffset = $offset;
            array_pop($newpacket->additional);
            $newpacket->header->arcount--;
            $newpacket->compnames = array();

            /*
             * Add the request MAC if present (used to validate responses).
             */
            if (isset($this->request_mac)) {
                $sigdata .= pack('H*', $this->request_mac);
            }
            $sigdata .= $newpacket->data();

            /*
             * Don't compress the record (key) name.
             */
            $tmppacket = new Packet;
            $sigdata .= $tmppacket->dn_comp(strtolower($this->name), 0);

            $sigdata .= pack('n', DNS::classesbyname(strtoupper($this->class)));
            $sigdata .= pack('N', $this->ttl);

            /*
             * Don't compress the algorithm name.
             */
            $tmppacket->compnames = array();
            $sigdata .= $tmppacket->dn_comp(strtolower($this->algorithm), 0);

            $sigdata .= pack('nN', 0, $this->time_signed);
            $sigdata .= pack('n', $this->fudge);
            $sigdata .= pack('nn', $this->error, $this->other_len);

            if (strlen($this->other_data)) {
                $sigdata .= pack('nN', 0, $this->other_data);
            }

            $this->mac = mhash(MHASH_MD5, $sigdata, $key);
            $this->mac_size = strlen($this->mac);

            /*
             * Don't compress the algorithm name.
             */
            unset($tmppacket);
            $tmppacket = new Packet;
            $rdata .= $tmppacket->dn_comp(strtolower($this->algorithm), 0);

            $rdata .= pack('nN', 0, $this->time_signed);
            $rdata .= pack('nn', $this->fudge, $this->mac_size);
            $rdata .= $this->mac;

            $rdata .= pack(
                'nnn',
                $packet->header->id,
                $this->error,
                $this->other_len
            );

            if ($this->other_data) {
                $rdata .= pack('nN', 0, $this->other_data);
            }
        }

        return $rdata;
    }

    public function error()
    {
        if ($this->error != 0) {
            $rcode = DNS::rcodesbyval($error);
        }

        return $rcode;
    }
}
