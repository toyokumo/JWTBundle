<?php

namespace Toyokumo\JWTBundle;

use Exception;
use InvalidArgumentException;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Toyokumo\JWTBundle\Exception\InvalidJWTException;
use Toyokumo\JWTBundle\Exception\NotVerifiedJWTException;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * Class JWTService
 * @package Toyokumo\JWTBundle
 */
class JWTService
{
    private JWKSet $jwkSet;

    private JWSBuilder $jwsBuilder;

    private CompactSerializer $compactSerializer;

    private JWSVerifier $jwsVerifier;

    private JWSSerializerManager $serializerManager;

    private HeaderCheckerManager $headerCheckerManager;

    private ClaimCheckerManager $claimCheckerManager;

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
        $this->jwsBuilder = new JWSBuilder(new AlgorithmManager([
            new HS256()
        ]));
        $this->compactSerializer = new CompactSerializer();
        $this->jwsVerifier = new JWSVerifier(new AlgorithmManager([
            new HS256()
        ]));
        $this->serializerManager = new JWSSerializerManager([
            new CompactSerializer()
        ]);
        // https://web-token.spomky-labs.com/the-components/header-checker#header-checker-manager
        $this->headerCheckerManager = new HeaderCheckerManager([
            new AlgorithmChecker(['HS256']),
            // We want to verify that the header "alg" (algorithm)
            // is present and contains "HS256"
        ],
            [
                new JWSTokenSupport(), // Adds JWS token type support
            ]);
        // https://web-token.spomky-labs.com/the-components/claim-checker#claim-checker-manager
        $this->claimCheckerManager = new ClaimCheckerManager(
            [
                new IssuedAtChecker(),
                new NotBeforeChecker(),
                new ExpirationTimeChecker(),
            ]
        );
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

        $claims['iat'] = $now;
        $claims['nbf'] = $now;
        $claims['exp'] = $now + $exp;
        $payload = JsonConverter::encode($claims);

        $jws = $this->jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($jwk, ['alg' => $jwk->get('alg'), 'kid' => $kid] )
            ->build();

        return $this->compactSerializer->serialize($jws);
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
            $jws = $this->serializerManager->unserialize($token);
            // header validation
            $this->headerCheckerManager->check($jws, 0, ['alg', 'kid']);
            // payload validation
            $claims = JsonConverter::decode($jws->getPayload());
            $this->claimCheckerManager->check($claims);
            // signature validation
            $signatures = $jws->getSignatures();
            $signature = $signatures[0];
            $kid = $signature->getProtectedHeaderParameter('kid');
            $jwk = $this->jwkSet->get($kid);
            $isVerified = $this->jwsVerifier->verifyWithKey($jws, $jwk, 0);
            if (!$isVerified) {
                throw new NotVerifiedJWTException('Token is not verified.');
            }
        } catch (InvalidArgumentException $e) {
            // 表記揺れがあるので str_contains で対応
            if (str_contains($e->getMessage(), 'Unsupported input')) {
                throw new NotVerifiedJWTException('Token is not verified.');
            }

            // 表記揺れがあるので str_contains で対応
            if (str_contains($e->getMessage(), 'Undefined index')) {
                throw new NotVerifiedJWTException('Token is not verified.');
            }
            throw $e;
        } catch (Exception $e) {
            if ($e->getMessage() === 'Invalid signature') {
                throw new NotVerifiedJWTException('Token is not verified.');
            }
            throw $e;
        }

        return $claims[$claimKey];
    }
}
