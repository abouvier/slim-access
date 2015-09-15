<?php
/*
	Access.php - Access control middleware for Slim framework
	Copyright 2015 abouvier <abouvier@student.42.fr>

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

namespace Slim\Middleware;

class Access extends \Slim\Middleware
{
	const ALLOW = true;
	const DENY = false;

	protected $settings;

	public function __construct(array $settings = [])
	{
		$defaults = [
			'callback' => null,
			'list' => [],
		];
		$this->settings = $settings + $defaults;
	}

	public function allow($cidr)
	{
		$this->settings['list'][$cidr] = self::ALLOW;
		return $this;
	}

	public function deny($cidr)
	{
		$this->settings['list'][$cidr] = self::DENY;
		return $this;
	}

	public function call()
	{
		foreach ($this->settings['list'] as $cidr => $allow) {
			$cidr = strtolower(trim($cidr));
			if ($cidr == 'all' or self::cidrMatch(
				$cidr,
				$this->app->environment['REMOTE_ADDR']
			)) {
				if (!$allow)
					break;
				$this->next->call();
				return;
			}
		}
		if (is_callable($this->settings['callback'])) {
			$this->settings['callback']();
			return;
		}
		$this->app->response->setStatus(403);
	}

	public static function cidrMatch($cidr, $address)
	{
		list($subnet, $slash, $size) = preg_split(
			'@(/|$)@',
			$cidr,
			2,
			PREG_SPLIT_DELIM_CAPTURE
		);
		if (filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$size = 32 - intval($slash ? $size : 32);
			return ip2long($subnet) == (ip2long($address) & (-1 << $size));
		} elseif (filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
			$size = intval($slash ? $size : 128);
			return inet_pton($subnet) == (inet_pton($address) & pack(
				'H*',
				str_pad(
					str_repeat('f', $size / 4) . ['', '8', 'c', 'e'][$size % 4],
					32,
					'0'
				)
			));
		}
		return false;
	}
}
