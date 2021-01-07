<?php

namespace Plumpboy\EmailValidate;

use Illuminate\Support\ServiceProvider;
use Plumpboy\EmailValidate\SMTPEmailValidator;

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
        $this->app['emailvalidate']->debug = $this->app['config']['app.debug'];

        if ($this->app['config']['mail.validate.use_jp_style']) {
            \Swift_DependencyContainer::getInstance()
                ->register('email.validator')
                ->asSharedInstanceOf('Plumpboy\EmailValidate\JpEmailValidator');
        }
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->registerSMTPEmailValidator();
    }

    /**
     * Register email address SMTPValidator.
     *
     * @return void
     */
    protected function registerSMTPEmailValidator()
    {
        $this->app->singleton('emailvalidate', function ($app) {
            return new SMTPEmailValidator();
        });
    }
}
