**A Library extending https://github.com/semplon/php-smtp-email-validation**

# What It Does ?
> Check if email address exists via SMTP.

## Requirement

- php >= 5.3

## Installation

- composer require plumboy/emailvalidate

## Usage

```php
...
use Plumpboy\EmailValidate\ValidateEmailViaSMTP;
...
	// the email to validate
	$email = 'user@example.com';
	// an optional sender
	$sender = 'user@mydomain.com';
	// instantiate the class
	$SMTPValidator = new ValidateEmailViaSMTP();
	// turn on debugging if you want to view the SMTP transaction
	$SMTPValidator->debug = true;
	// do the validation
	$results = $SMTPValidator->validate(array($email), $sender);
	// view results
	echo $email.' is '.($results[$email] ? 'valid' : 'invalid')."\n";

	// send email?
	if ($results[$email]) {
		//mail($email, 'Confirm Email', 'Please reply to this email to confirm', 'From:'.$sender."\r\n"); // send email
	} else {
		echo 'The email addresses you entered is not valid';
	}
```
### Laravel

For projects use laravel version < 5.5, add below code into **config/app.php**.
```php
...
'providers' => [
	...
    Plumpboy\EmailValidate\EmailValidateServiceProvider::class,
    ...
],
...
```
You also can use below syntax in laravel.

```php
$result = email_exists([$email], $sender); // use helper
```

```php
...
use Plumpboy\EmailValidate\EmailValidator;
...
$result = EmailValidator::validate([$email], $sender); // use facade
```

```php
$result = \EmailValidator::validate([$email], $sender); // or alias
```

## Contribute

- Fork the repository and make changes on your fork in a feature branch.
- Commit messages must start with a capitalized and short summary.
- After every commit, make sure the test suite passes.
- Contributor sends pull request to release/develop branch, ask another contributor to check if possible.
- Don't push private keys, logs or any unnecessary files to git repository
- Merge when pull request got 2 OK from contributors and CI build is green.
- Merge develop to master to release final version.

## License

http://creativecommons.org/licenses/by/2.0/