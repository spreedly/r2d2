require 'openssl'
require 'base64'
require 'hkdf'

module R2D2
  class PaymentToken

    attr_accessor :data, :ephemeral_public_key, :tag

    class TagVerificationError < StandardError; end;
    class DecryptedMessageUnparseableError < StandardError; end;
    class DecryptionError < StandardError; end;

    def initialize(token_attrs)
      self.ephemeral_public_key = Base64.decode64(token_attrs["ephemeralPublicKey"])
      self.tag = Base64.decode64(token_attrs["tag"])
      self.data = Base64.decode64(token_attrs["data"])
    end

    def decrypt(private_key_pem)
      digest = OpenSSL::Digest.new('sha256')
      private_key = OpenSSL::PKey::EC.new(private_key_pem)

      shared_secret = self.class.generate_shared_secret(private_key, ephemeral_public_key)

      # derive the symmetric_encryption_key and mac_key
      hkdf_keys = self.class.derive_hkdf_keys(ephemeral_public_key, shared_secret);

      # verify the tag is a valid value
      self.class.verify_mac(digest, hkdf_keys[:mac_key], data, tag)

      begin
        decrypted_message = JSON.parse(self.class.decrypt_message(data, hkdf_keys[:symmetric_encryption_key]))
      rescue JSON::ParserError
        raise DecryptedMessageUnparseableError
      rescue
        raise DecryptionError
      end

      payment_token = self.class.format_results(decrypted_message)

      JSON.generate(payment_token)
    end

    class << self

      def generate_shared_secret(private_key, ephemeral_public_key)
        ec = OpenSSL::PKey::EC.new('prime256v1')
        bn = OpenSSL::BN.new(ephemeral_public_key, 2)
        point = OpenSSL::PKey::EC::Point.new(ec.group, bn)
        private_key.dh_compute_key(point)
      end

      def derive_hkdf_keys(ephemeral_public_key, shared_secret)
        key_material = ephemeral_public_key + shared_secret;
        hkdf = HKDF.new(key_material, :algorithm => 'SHA256', :info => 'Android')
        hkdf_keys = {
          :symmetric_encryption_key => hkdf.next_bytes(16),
          :mac_key => hkdf.next_bytes(16)
        }
      end

      def verify_mac(digest, mac_key, data, tag)
        mac = OpenSSL::HMAC.digest(digest, mac_key, data)
        raise TagVerificationError unless mac == tag
      end

      def decrypt_message(encrypted_data, symmetric_key)
        decipher = OpenSSL::Cipher::AES128.new(:CTR)
        decipher.decrypt
        decipher.key = symmetric_key
        decipher.auth_data = ""
        payload = decipher.update(encrypted_data) + decipher.final
        payload.unpack('U*').collect { |el| el.chr }.join
      end

      def format_results(payment_token)
        payment_token["cryptogram"] = payment_token["3dsCryptogram"]
        payment_token["eciIndicator"] = payment_token["3dsEciIndicator"]
        payment_token.delete("3dsEciIndicator")
        payment_token.delete("3dsCryptogram")
        payment_token
      end

    end
  end
end
