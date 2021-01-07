<?php

use Plumpboy\EmailValidate\EmailValidator;

if (!function_exists('email_exists')) {
    /**
     * Call the given Closure with the given value then return the value.
     *
     * @param  mixed  $value
     * @param  callable|null  $callback
     * @return mixed
     */
    function email_exists($email_addresses, $sender = null)
    {
        return EmailValidator::validate($email_addresses, $sender);
    }
}

if (!function_exists('validate_jp_email')) {
    function validate_jp_email($email) {
        $strict = false;
        $dot_string = $strict ?
            '(?:[A-Za-z0-9!#$%&*+=?^_`{|}~\'\\/-]|(?<!\\.|\\A)\\.(?!\\.|@))' :
            '(?:[A-Za-z0-9!#$%&*+=?^_`{|}~\'\\/.-])'
        ;
        $quoted_string = '(?:\\\\\\\\|\\\\"|\\\\?[A-Za-z0-9!#$%&*+=?^_`{|}~()<>[\\]:;@,. \'\\/-])';
        $ipv4_part = '(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])';
        $ipv6_part = '(?:[A-fa-f0-9]{1,4})';
        $fqdn_part = '(?:[A-Za-z](?:[A-Za-z0-9-]{0,61}?[A-Za-z0-9])?)';
        $ipv4 = "(?:(?:{$ipv4_part}\\.){3}{$ipv4_part})";
        $ipv6 = '(?:' .
            "(?:(?:{$ipv6_part}:){7}(?:{$ipv6_part}|:))" . '|' .
            "(?:(?:{$ipv6_part}:){6}(?::{$ipv6_part}|:{$ipv4}|:))" . '|' .
            "(?:(?:{$ipv6_part}:){5}(?:(?::{$ipv6_part}){1,2}|:{$ipv4}|:))" . '|' .
            "(?:(?:{$ipv6_part}:){4}(?:(?::{$ipv6_part}){1,3}|(?::{$ipv6_part})?:{$ipv4}|:))" . '|' .
            "(?:(?:{$ipv6_part}:){3}(?:(?::{$ipv6_part}){1,4}|(?::{$ipv6_part}){0,2}:{$ipv4}|:))" . '|' .
            "(?:(?:{$ipv6_part}:){2}(?:(?::{$ipv6_part}){1,5}|(?::{$ipv6_part}){0,3}:{$ipv4}|:))" . '|' .
            "(?:(?:{$ipv6_part}:){1}(?:(?::{$ipv6_part}){1,6}|(?::{$ipv6_part}){0,4}:{$ipv4}|:))" . '|' .
            "(?::(?:(?::{$ipv6_part}){1,7}|(?::{$ipv6_part}){0,5}:{$ipv4}|:))" .
        ')';
        $fqdn = "(?:(?:{$fqdn_part}\\.)+?{$fqdn_part})";
        $local = "({$dot_string}++|(\"){$quoted_string}++\")";
        $domain = "({$fqdn}|\\[{$ipv4}]|\\[{$ipv6}]|\\[{$fqdn}])";
        $pattern = "/\\A{$local}@{$domain}\\z/";

        return preg_match($pattern, $email, $matches) &&
            (
                !empty($matches[2]) && !isset($matches[1][66]) && !isset($matches[0][256]) ||
                !isset($matches[1][64]) && !isset($matches[0][254])
            )
        ;
    }
}
