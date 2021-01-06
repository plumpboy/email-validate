<?php

 /**
 * Validate Email Addresses Via SMTP
 * This queries the SMTP server to see if the email address is accepted.
 * @copyright http://creativecommons.org/licenses/by/2.0/ - Please keep this comment intact
 */

namespace Plumpboy\EmailValidate;

use Illuminate\Support\Facades\Facade;

class EmailValidator extends Facade
{
	/**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'emailvalidate';
    }
}
