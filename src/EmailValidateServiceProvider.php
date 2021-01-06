<?php

namespace Plumpboy\EmailValidate;

use Illuminate\Support\ServiceProvider;
use Plumpboy\EmailValidate\ValidateEmailViaSMTP;

class EmailValidateServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        $this->app['emailvalidate']->setSenderEmail($this->app['config']['mail.from.address']);
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->registerSMTPValidator();
    }

    /**
     * Register email address SMTPValidator.
     *
     * @return void
     */
    protected function registerSMTPValidator()
    {
        $this->app->singleton('emailvalidate', function ($app) {
            return new ValidateEmailViaSMTP();
        });
    }
}
