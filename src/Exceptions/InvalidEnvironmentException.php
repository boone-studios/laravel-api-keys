<?php

namespace BooneStudios\ApiKeys\Exceptions;

use InvalidArgumentException;

class InvalidEnvironmentException extends InvalidArgumentException
{
    /**
     * Build the exception for an environment value that exceeds the column length.
     *
     * @param  string  $environment
     * @param  int  $maxLength
     * @return self
     */
    public static function tooLong(string $environment, int $maxLength): self
    {
        return new self(sprintf(
            'The resolved environment value [%s] is %d characters long, which exceeds the maximum of %d characters allowed by the api_keys.environment column. Check your configured environment resolver.',
            $environment,
            strlen($environment),
            $maxLength
        ));
    }
}
