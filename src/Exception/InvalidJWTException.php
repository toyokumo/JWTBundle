<?php

namespace Toyokumo\JWTBundle\Exception;

use Exception;

/**
 * Class InvalidJWTException
 * Verified JWT containing invalid contents
 * ex：
 * - exceeding exp claim
 * @package AppBundle\Exception
 */
class InvalidJWTException extends Exception
{
    /**
     * InvalidJWTException constructor.
     * @param string $message
     * @param int $code
     * @param Exception|null $previous
     */
    public function __construct(
        string $message,
        $code = 0,
        Exception $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }
}
