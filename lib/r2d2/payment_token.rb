# frozen_string_literal: true
require 'openssl'
require 'base64'
require 'hkdf'

module R2D2
  class PaymentToken

    attr_accessor :encrypted_message, :ephemeral_public_key, :tag

    class TagVerificationError < StandardError; end;
    SALT = "\x00" * 32

    def initialize(token_attrs)
      self.ephemeral_public_key = token_attrs["ephemeralPublicKey"]
      self.tag = token_attrs["tag"]
      self.encrypted_message = token_attrs["encryptedMessage"]
    end

    def decrypt(private_key_pem)
      digest = OpenSSL::Digest.new('sha256')
      private_key = OpenSSL::PKey::EC.new(private_key_pem)

      shared_secret = self.class.generate_shared_secret(private_key, ephemeral_public_key)

      # derive the symmetric_encryption_key and mac_key
      hkdf_keys = self.class.derive_hkdf_keys(ephemeral_public_key, shared_secret);

      # verify the tag is a valid value
      self.class.verify_mac(digest, hkdf_keys[:mac_key], encrypted_message, tag)

      self.class.decrypt_message(encrypted_message, hkdf_keys[:symmetric_encryption_key])
    end

    class << self

      def generate_shared_secret(private_key, ephemeral_public_key)
        ec = OpenSSL::PKey::EC.new('prime256v1')
        bn = OpenSSL::BN.new(Base64.decode64(ephemeral_public_key), 2)
        point = OpenSSL::PKey::EC::Point.new(ec.group, bn)
        private_key.dh_compute_key(point)
      end

      def derive_hkdf_keys(ephemeral_public_key, shared_secret)
        key_material = Base64.decode64(ephemeral_public_key) + shared_secret
        hkdf = HKDF.new(key_material, algorithm: 'SHA256', info: 'Android', salt: SALT).next_bytes(32)
        {
          symmetric_encryption_key: hkdf[0, 16],
          mac_key: hkdf[16, 16]
        }
      end

      def verify_mac(digest, mac_key, encrypted_message, tag)
        mac = OpenSSL::HMAC.digest(digest, mac_key, Base64.decode64(encrypted_message))
        raise TagVerificationError unless secure_compare(mac, Base64.decode64(tag))
      end

      def decrypt_message(encrypted_data, symmetric_key)
        decipher = OpenSSL::Cipher::AES128.new(:CTR)
        decipher.decrypt
        decipher.key = symmetric_key
        decipher.auth_data = ""
        payload = decipher.update(Base64.decode64(encrypted_data)) + decipher.final
        payload.unpack('U*').collect { |el| el.chr }.join
      end

      if defined?(FastSecureCompare)
        def secure_compare(a, b)
          FastSecureCompare.compare(a, b)
        end
      else
        # constant-time comparison algorithm to prevent timing attacks; borrowed from ActiveSupport::MessageVerifier
        def secure_compare(a, b)
          return false unless a.bytesize == b.bytesize

          l = a.unpack("C#{a.bytesize}")

          res = 0
          b.each_byte { |byte| res |= byte ^ l.shift }
          res == 0
        end
      end
    end
  end
end
