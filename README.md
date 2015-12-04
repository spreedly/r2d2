# R2D2

R2D2 is a Ruby library for decrypting Android Pay payment tokens.

## Install

Add to your `Gemfile`:

```ruby
gem "android_pay", git: "https://github.com/spreedly/android_pay.git"
```

## Usage

AndroidPay works by:

1. Initializing an instance of `R2D2::PaymentToken` with the hash of values present in the Android Pay token string. Example:

```
{

“encryptedMessage”: “ZW5jcnlwdGVkTWVzc2FnZQ==”,

“ephemeralPublicKey”: “ZXBoZW1lcmFsUHVibGljS2V5”,

“tag”: ”c2lnbmF0dXJl”

}
```

2. Decrypting the token using the token's ephemeral public key and private key (the latter of which, at least, is managed by a third-party such as a gateway or independent processor like [Spreedly](https://spreedly.com)).

```ruby
require "android_pay"

# token_json = raw token string you get from Android Pay
token_attrs = JSON.parse(token_json)
token = R2D2::PaymentToken.new(token_attrs)

private_key_pem = File.read("private_key.pem")

decrypted_json = token.decrypt private_key_pem
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

## Testing

```session
$ ruby test/payment_token_test.rb
...
5 tests, 18 assertions, 0 failures, 0 errors, 0 skips
```

