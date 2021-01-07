<?php

namespace Plumpboy\EmailValidate;

use Egulias\EmailValidator\EmailValidator;
use Egulias\EmailValidator\Validation\EmailValidation;

class JpEmailValidator extends EmailValidator
{
    public function isValid($email, EmailValidation $emailValidation)
    {
       	// Ommit the second parameter $emailValidation and do some other magic
        return validate_jp_email($email);
    }
}
