# JWTBundle
Generating and Interpreting JWT token.

## Usage

### JWTService

1. Set JWK information via .yml file.
```
# key_info.yml
parameters:
jwt_keys:
# for HS256
  key_name_for_HS256_key:
    kid: current_kid
    alg: HS256
    secret: 'secret string with more than 32 chars.'
# for RS256 or ES256
  key_name_for_RS256_or_ES256_key:
    kid: current_kid
    alg: RS256 or ES256
    filename: 'public or private key filename'
    passphrase: 'passphrase to decode key'
```

2. Place .yml and key files in the same directory.

3. Set arguments
```
# jwt.yml
services:
  Toyokumo\JWTBundle\JWTService:
    arguments:
      $keyDirPath: 'path/to/key_info.yml and key files'
      $jwkInfos: '%jwt_keys%' # JWK information defined in key_info.yml
```
