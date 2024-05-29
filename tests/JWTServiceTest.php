<?php

namespace Toyokumo\JWTBundle;

use Jose\Component\Checker\InvalidClaimException;
use PHPUnit\Framework\TestCase;
use Toyokumo\JWTBundle\Exception\InvalidJWTException;
use Toyokumo\JWTBundle\Exception\NotVerifiedJWTException;

class JWTServiceTest extends TestCase
{
    private JWTService $jwt;

    /**
     * JWTServiceTest constructor.
     * @param null $name
     * @param array $data
     * @param string $dataName
     */
    public function __construct($name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        $jwkInfo = [
            [
                'kid' => 'test_key',
                'alg' => 'HS256',
                'secret' => '01234567890123456789012345678901'
            ]
        ];
        $this->jwt = new JWTService('./tests/jwt', $jwkInfo);
    }

    /**
     * @throws InvalidJWTException
     * @throws NotVerifiedJWTException
     */
    public function testGenerateAndDecodeJWSToken(): void
    {
        $token = $this->jwt->generateJWSToken(['hoge' => 'fuga'], 'test_key', 3600);
        $res = $this->jwt->extractValueFromToken($token, 'hoge');

        $this->assertEquals('fuga', $res);
    }

    /**
     * @throws InvalidJWTException
     * @throws NotVerifiedJWTException
     */
    public function testExpireJWSToken(): void
    {
        $token = $this->jwt->generateJWSToken(['hoge' => 'fuga'], 'test_key', -1); // exp = -1 means expire right now

        $this->expectException(InvalidClaimException::class);
        $this->jwt->extractValueFromToken($token, 'hoge');
    }

    /**
     * @throws InvalidJWTException
     * @throws NotVerifiedJWTException
     */
    public function testLackedJWSToken(): void
    {
        $token = $this->jwt->generateJWSToken(['hoge' => 'fuga'], 'test_key', 3600);
        $token = substr($token, 1);

        $this->expectException(NotVerifiedJWTException::class);
        $this->jwt->extractValueFromToken($token, 'hoge');
    }

    /**
     * @throws InvalidJWTException
     * @throws NotVerifiedJWTException
     */
    public function testModifiedJWSToken(): void
    {
        $token = $this->jwt->generateJWSToken(['hoge' => 'fuga'], 'test_key', 3600);

        // 改変: alg = none
        [, $payload, $sig] = explode('.', $token);
        $head = '{"alg": "none", "kid": "test_key"}';
        $head = base64_encode($head);
        $tokenModified = implode('.', [$head, $payload, $sig]);

        $this->expectException(NotVerifiedJWTException::class);
        $this->jwt->extractValueFromToken($tokenModified, 'hoge');

        // 改変: HS256 => RS256
        [, $payload, $sig] = explode('.', $token);
        $head = '{"alg": "RS256", "kid": "test_key"}';
        $head = base64_encode($head);
        $tokenModified = implode('.', [$head, $payload, $sig]);

        $this->expectException(NotVerifiedJWTException::class);
        $this->jwt->extractValueFromToken($tokenModified, 'hoge');

        // 改変: kid 削除
        [, $payload, $sig] = explode('.', $token);
        $head = '{"alg": "HS256"}';
        $head = base64_encode($head);
        $tokenModified = implode('.', [$head, $payload, $sig]);

        $this->expectException(NotVerifiedJWTException::class);
        $this->jwt->extractValueFromToken($tokenModified, 'hoge');

        // 改変: invalid kid
        [, $payload, $sig] = explode('.', $token);
        $head = '{"alg": "HS256", "kid": "invalid_kid"}';
        $head = base64_encode($head);
        $tokenModified = implode('.', [$head, $payload, $sig]);

        $this->expectException(NotVerifiedJWTException::class);
        $this->jwt->extractValueFromToken($tokenModified, 'hoge');
    }
}
