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
    	if (!is_array($email_addresses)) {
    		$email_addresses = [$email_addresses];
    	}

        return EmailValidator::validate($email_addresses, $sender);
    }
}
