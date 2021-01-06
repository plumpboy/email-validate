<?php

 /**
 * Validate Email Addresses Via SMTP
 * This queries the SMTP server to see if the email address is accepted.
 * @copyright http://creativecommons.org/licenses/by/2.0/ - Please keep this comment intact
 */

namespace Plumpboy\EmailValidate;

use Plumpboy\EmailValidate\Net\DNS;

class ValidateEmailViaSMTP
{
    /**
     * PHP Socket resource to remote MTA
     * @var resource $sock
    */
    public $sock;

    /**
     * Current User being validated
     */
    public $user;
    /**
     * Current domain where user is being validated
     */
    public $domain;
    /**
     * List of domains to validate users on
     */
    public $domains;
    /**
     * SMTP Port
     */
    public $port = 25;
    /**
     * Maximum Connection Time to wait for connection establishment per MTA
     */
    public $max_conn_time = 30;
    /**
     * Maximum time to read from socket before giving up
     */
    public $max_read_time = 5;

    /**
     * username of sender
     */
    public $from_user = 'user';
    /**
     * Host Name of sender
     */
    public $from_domain = 'localhost';

    /**
     * Nameservers to use when make DNS query for MX entries
     * @var Array $nameservers
     */
    public $nameservers = [
        '192.168.0.1',
    ];

    public $debug = false;

    /**
     * @param $email Array[optional] List of Emails to Validate
     * @param $sender String[optional] Email of validator
     */
    public function __construct($emails = false, $sender = false)
    {
        if ($emails) {
            $this->setEmails($emails);
        }
        if ($sender) {
            $this->setSenderEmail($sender);
        }
    }

    private function _parseEmail($email)
    {
        $parts = explode('@', $email);
        $domain = array_pop($parts);
        $user= implode('@', $parts);

        return array($user, $domain);
    }

    /**
     * Set the Emails to validate
     * @param $emails Array List of Emails
     */
    public function setEmails($emails)
    {
        foreach ($emails as $email) {
            list($user, $domain) = $this->_parseEmail($email);
            if (!isset($this->domains[$domain])) {
                $this->domains[$domain] = array();
            }
            $this->domains[$domain][] = $user;
        }
    }

    /**
     * Set the Email of the sender/validator
     * @param $email String
     */
    public function setSenderEmail($email)
    {
        $parts = $this->_parseEmail($email);
        $this->from_user = $parts[0];
        $this->from_domain = $parts[1];
    }

    /**
    * Validate Email Addresses
    * @param String $emails Emails to validate (recipient emails)
    * @param String $sender Sender's Email
    *
    * @return Array Associative List of Emails and their validation results
    */
    public function validate($emails = false, $sender = false)
    {
        $results = array();

        if ($emails) {
            $this->setEmails($emails);
        }
        if ($sender) {
            $this->setSenderEmail($sender);
        }

        // query the MTAs on each Domain
        foreach ($this->domains as $domain => $users) {
            $mxs = array();

            // current domain being queried
            $this->domain = $domain;

            // retrieve SMTP Server via MX query on domain
            list($hosts, $mxweights) = $this->queryMX($domain);


            for ($n=0; $n < count($hosts); $n++) {
                $mxs[$hosts[$n]] = $mxweights[$n];
            }
            asort($mxs);

            // last fallback is the original domain
            $mxs[$this->domain] = 0;

            $this->debug(print_r($mxs, 1));

            $timeout = $this->max_conn_time;

            // try each host
            foreach ($mxs as $host => $v) {
                // connect to SMTP server
                $this->debug("try $host:$this->port\n");
                if ($this->sock = fsockopen($host, $this->port, $errno, $errstr, (float) $timeout)) {
                    stream_set_timeout($this->sock, $this->max_read_time);
                    break;
                }
            }

            // did we get a TCP socket
            if ($this->sock) {
                $reply = fread($this->sock, 2082);
                $this->debug("<<<\n$reply");

                preg_match('/^([0-9]{3}) /ims', $reply, $matches);
                $code = isset($matches[1]) ? $matches[1] : '';

                if ($code != '220') {
                    // MTA gave an error...
                    foreach ($users as $user) {
                        $results[$user.'@'.$domain] = false;
                    }
                    continue;
                }

                // say helo
                $this->send("HELO ".$this->from_domain);
                // tell of sender
                $this->send("MAIL FROM: <".$this->from_user.'@'.$this->from_domain.">");

                // ask for each recepient on this domain
                foreach ($users as $user) {

                    // ask of recepient
                    $reply = $this->send("RCPT TO: <".$user.'@'.$domain.">");

                    // get code and msg from response
                    preg_match('/^([0-9]{3}) /ims', $reply, $matches);
                    $code = isset($matches[1]) ? $matches[1] : '';

                    if ($code == '250') {
                        // you received 250 so the email address was accepted
                        $results[$user.'@'.$domain] = true;
                    } elseif ($code == '451' || $code == '452') {
                        // you received 451 so the email address was greylisted (or some temporary error occured on the MTA) - so assume is ok
                        $results[$user.'@'.$domain] = true;
                    } else {
                        $results[$user.'@'.$domain] = false;
                    }
                }

                // reset before quit
                $this->send("RSET");

                // quit
                $this->send("quit");
                // close socket
                fclose($this->sock);
            } else {
                $this->debug('Error: Could not connect to a valid mail server for this email address: ' . $user.'@'.$domain);
            }
        }
        return $results;
    }

    protected function send($msg)
    {
        fwrite($this->sock, $msg."\r\n");

        $reply = fread($this->sock, 2082);

        $this->debug(">>>\n$msg\n");
        $this->debug("<<<\n$reply");

        return $reply;
    }

    /**
     * Query DNS server for MX entriesg
     * @return
     */
    protected function queryMX($domain)
    {
        $hosts = array();
        $mxweights = array();
        if (function_exists('getmxrr')) {
            getmxrr($domain, $hosts, $mxweights);
        } else {
            $resolver = new Resolver();
            $resolver->debug = $this->debug;
            // nameservers to query
            $resolver->nameservers = $this->nameservers;
            $resp = $resolver->query($domain, 'MX');
            if ($resp) {
                foreach ($resp->answer as $answer) {
                    $hosts[] = $answer->exchange;
                    $mxweights[] = $answer->preference;
                }
            }
        }

        return array($hosts, $mxweights);
    }

    /**
     * Simple function to replicate PHP 5 behaviour. http://php.net/microtime
     */
    public function microtime_float()
    {
        list($usec, $sec) = explode(" ", microtime());

        return ((float)$usec + (float)$sec);
    }

    public function debug($str)
    {
        if ($this->debug) {
            echo '<pre>'.htmlentities($str).'</pre>';
        }
    }
}
