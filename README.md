# R2D2

[![CircleCI](https://circleci.com/gh/spreedly/r2d2.svg?style=svg)](https://circleci.com/gh/spreedly/r2d2)

R2D2 is a Ruby library for decrypting Google Pay and Android Pay payment tokens.

## Ruby support

Currently, Ruby v2.2 or later is supported.

## Install

Add to your `Gemfile`:

```ruby
gem 'r2d2', git: 'https://github.com/spreedly/r2d2.git'
```

## Google Pay Usage

For Google Pay, R2D2 requires the token values in the form of a JSON hash, your `recipient_id`, Google's `verification_keys` 
for the appropriate environment, and your private key.

Example Google Pay token values:

```json
{
  "signature": "MEYCIQD5mAtwoptfXuDnEVvtSbPmRnkw94GXEHjog24SfIe4rAIhAKLeSY4xcHLK1liBoZFaeZG+FrqawI7Id2mJXwddP3KH",
  "protocolVersion": "ECv1",
  "signedMessage": "{\"encryptedMessage\":\"jzo38/Ufbt9qh/scrTJmG9v8Cgb7Y5S+zCTTbSou/NoLoE/XF9ixyIGNIspKkH4ulwwVX0/EoqKDKk86XDLw8qBjx1tfHefbLuhZbqkfu/8bs5D6QMz8LjcJU+EeXYcdZ+KeQ3jzrgS6B9CqEJJIF+PeySMJtTwF9Fh+X2sW4Yg0C34mHz0MHpVUpmzJZblTwzMkCVOdq7eMF9Ywb8kDnRFasMYALbRaEOMg2o9gXSfGEVPhS8ors4SRFcnLoVPfktHRJtY/UZEREJvGFY/s/wpmU9sRADYTMKQ/ChTMumT+1NG0r4XibDcaZjW/Wlz1Dwog+dNMYUblPjY613sBLtjoBbRDYYVuDn/TUYXOJwAgXoHFfMmvWm0ne0n9eXggxoaMFFgF5zXk9ZLl3FyH/hi3WWtsFt5sqQWgFdjsqTriL6i46m46hMaZ9gKZ8JQE912IG5kZts5L8XSMiG94Z3UiTA\\u003d\\u003d\",\"ephemeralPublicKey\":\"BIeq42AvLcEhz0oLmYdj++oBTS5PD131FAEgx4y91cwqbkZMUKADkzj2bD4MxneqgqFYirO29+y/G6YH9zmfjlk\\u003d\",\"tag\":\"sRILsawzbm53+9tVTh9ooBP5ivzxWki73UJbuOZ3IYY\\u003d\"}"
}
```

The `recipient_id` will be given to you by Google. Example: `merchant:12345678901234567890`. 

The `verification_keys` must be fetched from Google's servers for the appropriate environment:
- production: https://payments.developers.google.com/paymentmethodtoken/keys.json
- test: https://payments.developers.google.com/paymentmethodtoken/test/keys.json

It's a good idea to cache these keys for performance and resiliency. The `Cache-Control: max-age` directive must be 
respected to expire the cache. To prevent decryption failures by expiring caches, it's recommended by Google's 
[Tink](https://github.com/google/tink) reference library to pro-actively refresh the cache after half of the `max-age` 
duration has passed.
 
The JSON must be parsed into a Ruby hash before being passed to R2D2. Example:

```ruby
{
  "keys" =>
    [
      {
        "keyValue" => "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIsFro6K+IUxRr4yFTOTO+kFCCEvHo7B9IOMLxah6c977oFzX/beObH4a9OfosMHmft3JJZ6B3xpjIb8kduK4/A==", 
        "protocolVersion" => "ECv1"
      }
    ]
}
```

```ruby
require 'r2d2'

# token_attrs = Google Pay token values { "signature": "...", "protocolVersion": "...", ...}
token = R2D2.build_token(token_attrs, recipient_id: recipient_id, verification_keys: verification_keys)

private_key_pem = File.read('private_key.pem')
decrypted_json = token.decrypt(private_key_pem)

JSON.parse(decrypted_json)
# =>
{
  "gatewayMerchantId" => "exampleGatewayMerchantId",
  "messageExpiration" => "1528716120231", 
  "messageId" => "AH2EjtcpVGS3JvxlTP5kUbx3h0Laa30uVKjB9CqmnYiw8gZ-tpsxIoOdTbAU_DtCbkLVUPzkFeeqSbU1vTbAIAE4LlPHJqBiMMF4hZ5KRafml3764_6lK7aH7cQkIma40CI-rtCWTLCk",
  "paymentMethod" => "CARD",
  "paymentMethodDetails" =>
  {
    "expirationYear" => 2023,
    "expirationMonth" => 12,
    "pan" => "4111111111111111"
  }
}
```


## Android Pay Usage

R2D2 takes input in the form of the hash of Android Pay token values:

```json
{
  "encryptedMessage": "ZW5jcnlwdGVkTWVzc2FnZQ==",
  "ephemeralPublicKey": "ZXBoZW1lcmFsUHVibGljS2V5",
  "tag": "c2lnbmF0dXJl"
}
```

and the merchant's private key (which is managed by a third-party such as a gateway or independent processor like [Spreedly](https://spreedly.com)).

```ruby
require 'r2d2'

# token_json = raw token string you get from Android Pay { "encryptedMessage": "...", "tag": "...", ...}
token = R2D2.build_token(token_attrs)

private_key_pem = File.read('private_key.pem')
decrypted_json = token.decrypt(private_key_pem)

JSON.parse(decrypted_json)
# =>
{
  “dpan”: “4444444444444444”,
  “expirationMonth”: 10,
  “expirationYear”: 2015 ,
  “authMethod”: “3DS”,
  “3dsCryptogram”: “AAAAAA...”,
  “3dsEciIndicator”: “eci indicator”
}
```

## Performance

The library implements a constant time comparison algorithm for preventing timing attacks. The default pure ruby implementation is quite inefficient, but portable. If performance is a priority for you, you can use a faster comparison algorithm provided by the [fast_secure_compare](https://github.com/daxtens/fast_secure_compare).

To enable `FastSecureCompare` in your environment, add the following to your Gemfile:

```ruby
gem 'fast_secure_compare'
```

and require the extension in your application prior to loading r2d2:

```ruby
require 'fast_secure_compare/fast_secure_compare'
require 'r2d2'
```

Benchmarks illustrating the overhead of the pure Ruby version:

```
                          user     system      total        real
secure_compare        1.070000   0.010000   1.080000 (  1.231714)
fast secure_compare   0.050000   0.000000   0.050000 (  0.049753)
```

## Testing

```session
$ bundle exec rake
...
5 tests, 18 assertions, 0 failures, 0 errors, 0 skips
```

## Releasing

To cut a new gem:

### Setup RubyGems account

Make sure you have a [RubyGems account](https://rubygems.org) and have setup your local gem credentials with something like this:

```bash
$ curl -u rwdaigle https://rubygems.org/api/v1/api_key.yaml > ~/.gem/credentials; chmod 0600 ~/.gem/credentials
<enter rubygems account password>
```

If you are not yet listed as a gem owner, you will need to [request access](https://github.com/rwdaigle) from @rwdaigle.

### Release

Build and release the gem with (all changes should be committed and pushed to Github):

```bash
$ rake release
```

## Changelog

### v1.0.0

* Breaking Changes: API now decrypts both Google Pay and Android Pay tokens
* New method call to decrypt Android Pay tokens
* Additional arguments included for Google Pay tokens
* Update README.md

### v0.1.2

* Setup CircleCI for more exhaustive Ruby version compatibility tests
* Add gem release instructions

## Contributors

* [mrezentes](https://github.com/mrezentes)
* [rwdaigle](https://github.com/rwdaigle)
* [methodmissing](https://github.com/methodmissing)
* [bdewater](https://github.com/bdewater)
* [deedeelavinder](https://github.com/deedeelavinder)
