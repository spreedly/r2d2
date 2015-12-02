require 'openssl'
require 'base64'
require 'hkdf'

module Android_Pay
  class PaymentToken

    attr_accessor :data, :ephemeral_public_key, :tag


    def initialize(token_attrs)
      self.ephemeral_public_key = token_attrs["ephemeralPublicKey"]
      self.tag = token_attrs["tag"]
      self.data = token_attrs["data"]
    end

    def decrypt(ephemeral_public_key, private_key_pem)
      digest = OpenSSL::Digest.new('sha256')
      private_key = OpenSSL::PKey::EC.new(private_key_pem)

      shared_secret = self.class.generate_shared_secret(private_key, ephemeral_public_key)

      info = "Android".encode 'ASCII'

      key_material = Base64.decode64(ephemeral_public_key) + shared_secret;
      hkdf = HKDF.new(key_material, :algorithm => 'SHA256', :info => info)

      symmetricEncryptionKey = hkdf.next_bytes(16)
      mac_key = hkdf.next_bytes(16)

      verify_mac = OpenSSL::HMAC.digest(digest, mac_key, Base64.decode64(data))
      #TODO: handle the error if the tag is wrong

      # Return JSON string, up to caller to parse
      self.class.decrypt(Base64.decode64(data), symmetricEncryptionKey)
    end

    class << self

      def generate_shared_secret(private_key, ephemeral_public_key)
        epk = ephemeral_public_key;
        puts epk.encoding
        decoded_epk = Base64.decode64(epk)
        ec = OpenSSL::PKey::EC.new('prime256v1')
        bn = OpenSSL::BN.new(decoded_epk, 2) # bn = a Big Number
        point = OpenSSL::PKey::EC::Point.new(ec.group, bn) # the point on the elliptic curve
        private_key.dh_compute_key(point)
      end

      def decrypt(encrypted_data, symmetric_key)
        decipher = OpenSSL::Cipher::AES128.new(:CTR)
        decipher.decrypt
        decipher.key = symmetric_key
        decipher.auth_data = ""
        plain = decipher.update(encrypted_data) + decipher.final
        plain.unpack('U*').collect { |el| el.chr }.join
      end
    end
  end
end
