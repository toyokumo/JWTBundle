<?php

namespace Toyokumo\JWTBundle\Exception;

use Exception;

/**
 * Class NotVerifiedJWTException
 * Broken JWT
 * ex：
 * - fail to parse token
 * - invalid signature / no signature
 * @package AppBundle\Exception
 */
class NotVerifiedJWTException extends Exception
{
    /**
     * NotVerifiedJWTException constructor.
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
