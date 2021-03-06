<?php

namespace Toyokumo\JWTBundle;

use Exception;
use InvalidArgumentException;
use Toyokumo\JWTBundle\Exception\InvalidJWTException;
use Toyokumo\JWTBundle\Exception\NotVerifiedJWTException;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Easy\Build;
use Jose\Easy\Load;

/**
 * Class JWTService
 * @package Toyokumo\JWTBundle
 */
class JWTService
{
    private JWKSet $jwkSet;

    /**
     * JWTService constructor.
     * @param string $keyDirPath
     * @param array $jwkInfos
     */
    public function __construct(string $keyDirPath, array $jwkInfos)
    {
        if ('/' !== substr($keyDirPath, -1)) {
            $keyDirPath .= '/';
        }
        $jwks = [];
        foreach ($jwkInfos as $jwkInfo) {
            $kid = $jwkInfo['kid'];
            $alg = $jwkInfo['alg'];
            if ($alg === 'HS256') {
                $secret = $jwkInfo['secret'];
                $jwks[] = JWKFactory::createFromSecret($secret, [
                    'use' => 'sig',
                    'alg' => $alg,
                    'kid' => $kid,
                ]);
            } else {
                $filename = $jwkInfo['filename'];
                $passphrase = $jwkInfo['passphrase'];
                $jwks[] = JWKFactory::createFromKeyFile(
                    $keyDirPath . $filename,
                    $passphrase,
                    [
                        'use' => 'sig',
                        'alg' => $alg,
                        'kid' => $kid,
                    ]
                );
            }
        }
        $this->jwkSet = new JWKSet($jwks);
    }

    /**
     * @param array $claims
     * @param string $kid
     * @param int $exp
     * @return string
     */
    public function generateJWSToken(
        array $claims,
        string $kid,
        int $exp
    ): string {
        $now = time();

        $jwk = $this->jwkSet->get($kid);
        $jws = Build::jws()
            ->alg($jwk->get('alg'))
            ->header('kid', $kid)
            ->exp($now + $exp)
            ->iat($now)
            ->nbf($now);
        foreach ($claims as $key => $value) {
            $jws->claim($key, $value);
        }
        return $jws->sign($jwk);
    }

    /**
     * @param string $token
     * @param string $claimKey
     * @return mixed
     * @throws NotVerifiedJWTException
     * @throws InvalidJWTException
     * @throws Exception
     */
    public function extractValueFromToken(string $token, string $claimKey)
    {
        try {
            // Get kid for identifying jwk
            $signatures = (new CompactSerializer())
                ->unserialize($token)
                ->getSignatures();
            $signature = $signatures[0];
            if (!$signature->hasProtectedHeaderParameter('kid')) {
                throw new NotVerifiedJWTException('Token is not verified.');
            }
            $kid = $signature->getProtectedHeaderParameter('kid');
            if (!$this->jwkSet->has($kid)) {
                throw new NotVerifiedJWTException('Token is not verified.');
            }
            $jwk = $this->jwkSet->get($kid);

            $jwt = Load::jws($token)
                ->alg($jwk->get('alg'))
                ->exp()
                ->nbf()
                ->key($jwk)
                ->run();
        } catch (InvalidClaimException $e) {
            // token expiration etc..
            throw new InvalidJWTException('Token is invalid.');
        } catch (InvalidHeaderException $e) {
            // alg=none tampering etc..
            throw new NotVerifiedJWTException('Token is not verified.');
        } catch (InvalidArgumentException $e) {
            if ($e->getMessage() === 'Unsupported input') {
                // failed to decode token
                throw new NotVerifiedJWTException('Token is not verified.');
            }
            if ($e->getMessage() === 'Undefined index') {
                // there is no JWK corresponding to kid
                throw new NotVerifiedJWTException('Token is not verified.');
            }
            throw $e;
        } catch (Exception $e) {
            if ($e->getMessage() === 'Invalid signature') {
                throw new NotVerifiedJWTException('Token is not verified.');
            }
            throw $e;
        }

        return $jwt->claims->get($claimKey);
    }
}
