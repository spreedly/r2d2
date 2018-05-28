module R2D2
  Error = Class.new(StandardError)
  TagVerificationError = Class.new(R2D2::Error)

  module Util
    def generate_shared_secret(private_key, ephemeral_public_key)
      ec = OpenSSL::PKey::EC.new('prime256v1')
      bn = OpenSSL::BN.new(Base64.decode64(ephemeral_public_key), 2)
      point = OpenSSL::PKey::EC::Point.new(ec.group, bn)
      private_key.dh_compute_key(point)
    end

    def derive_hkdf_keys(ephemeral_public_key, shared_secret)
      key_material = Base64.decode64(ephemeral_public_key) + shared_secret
      hkdf = HKDF.new(key_material, algorithm: 'SHA256', info: 'Android')
      {
        symmetric_encryption_key: hkdf.next_bytes(16),
        mac_key: hkdf.next_bytes(16)
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
      decipher.update(Base64.decode64(encrypted_data)) + decipher.final
    end

    private

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
