# Slim Access

Access control middleware for Slim framework.

## Supported formats

* IPv4 and IPv6 addresses
* CIDR notation
* _all_ keyword

## Installation

    composer require abouvier/slim-access

## Usage

Only accept requests from localhost and the 192.168.1.0/24 subnet (except for 192.168.1.42).

```php
use \Slim\Middleware\Access;
// ...
$app = new \Slim\Slim();
// ...
$app->add(new Access([
	'::1' => Access::ALLOW,
	'127.0.0.1' => Access::ALLOW,
	'192.168.1.42' => Access::DENY,
	'192.168.1.0/24' => Access::ALLOW,
	'all' => Access::DENY
], function () use ($app) {
	$app->halt(403, 'You Shall Not Pass!!!');
}));
// ...
$app->run();
```
