<?php

namespace Signer\Manager\Interceptor;

use \Monolog\Logger;
use \Monolog\Formatter\LineFormatter;
use \Monolog\Handler\StreamHandler;

class MyLogger extends Logger
{
	
	function __construct($name)
	{
		$output = "[%datetime%] %channel%.%level_name%: %message%\n";
        $formatter = new LineFormatter($output);
        $streamHandler = new StreamHandler('php://stdout', Logger::DEBUG);
        $streamHandler->setFormatter($formatter);
        parent::__construct($name, [$streamHandler]);
	}
}