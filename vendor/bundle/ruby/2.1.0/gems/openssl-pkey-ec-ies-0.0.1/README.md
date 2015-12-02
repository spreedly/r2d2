# OpenSSL::PKey::EC::IES

IES implementation following ECIES-KEM specification in [ISO 18033-2](http://www.shoup.net/iso/).

This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/).

## Installation

Add this line to your application's Gemfile:

    gem 'openssl-pkey-ec-ies'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install openssl-pkey-ec-ies

## Usage

Prepare secret key using OpenSSL.

```
openssl ecparam -genkey -out ec_key.pem -name prime192v1
```

```ruby
ec = OpenSSL::PKey::EC::IES.new(test_key, "placeholder")
source = 'my secret'
cryptogram = ec.public_encrypt(source)  # => cryptogram in string
result = ec.private_decrypt(cryptogram) # => 'my secret'
```

## Contributing

1. Fork it ( https://github.com/webpay/openssl-pkey-ec-ies/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
