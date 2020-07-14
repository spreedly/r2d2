module R2D2
  class GooglePayTokenV2
    include Util

    attr_reader :protocol_version, :recipient_id, :signature, :signed_message, :intermediate_signing_key

    def initialize(token_attrs, recipient_id:, verification_keys:)
      @protocol_version = token_attrs['protocolVersion']
      @recipient_id = recipient_id
      @verification_keys = verification_keys
      @signature = token_attrs['signature']
      @signed_message = token_attrs['signedMessage']
      @intermediate_signing_key = token_attrs['intermediateSigningKey']
      @intermediate_key = JSON.parse(token_attrs['intermediateSigningKey']['signedKey'])
    end

    def decrypt(private_key_pem)
      verified = verify_and_parse_message

      private_key = OpenSSL::PKey::EC.new(private_key_pem)
      shared_secret = generate_shared_secret(private_key, verified['ephemeralPublicKey'])
      hkdf_keys = derive_hkdf_keys(verified['ephemeralPublicKey'], shared_secret, 'Google')

      verify_mac(hkdf_keys[:mac_key], verified['encryptedMessage'], verified['tag'])
      decrypted = JSON.parse(
        decrypt_message(verified['encryptedMessage'], hkdf_keys[:symmetric_encryption_key])
      )

      expired = decrypted['messageExpiration'].to_f / 1000.0 <= Time.now.to_f
      raise MessageExpiredError if expired

      decrypted
    end

    private

    def verify_and_parse_message
      raise SignatureInvalidError, 'intermediate certificate is expired' if intermediate_key_expired?
      check_signature

      JSON.parse(signed_message)
    end

    def check_signature
      intermediate_signatures = intermediate_signing_key[:signatures]
      signed_key_signature = ['Google', protocol_version, intermediate_signing_key[:signedKey]].map do |str|
        [str.length].pack('V') + str
      end.join

      # Check that a root signing key signed the intermediate
      root_key_verified = valid_intermediate_key_signatures?(
        verification_keys,
        intermediate_signatures,
        signed_key_signature
      )

      raise SignatureInvalidError, 'no valid signature of intermediate key' unless root_key_verified

      signed_string_message = ['Google', recipient_id, protocol_version, signed_message].map do |str|
        [str.length].pack('V') + str
      end.join

      # Check that the intermediate key signed the message
      pkey = OpenSSL::PKey::EC.new(Base64.strict_decode64(@intermediate_key['keyValue']))
      intermediate_key_verified = pkey.verify(OpenSSL::Digest::SHA256.new, Base64.strict_decode64(signature), signed_string_message)
      raise SignatureInvalidError, 'signature of signedMessage does not match' unless intermediate_key_verified

    end

    def valid_intermediate_key_signatures?(signing_keys, signatures, signed)
      signing_keys.product(signatures).each do |key, sig|
        return true if key.verify(OpenSSL::Digest::SHA256.new, Base64.strict_decode64(sig), signed)
      end
      false
    end

    def verification_keys
      root_signing_keys = @verification_keys['keys'].select do |key|
        key['protocolVersion'] == protocol_version
      end

      root_signing_keys.map! do |key|
        OpenSSL::PKey::EC.new(Base64.strict_decode64(key['keyValue']))
      end
    end

    def intermediate_key_expired?
      cur_millis = (Time.now.to_f * 1000).round
      @intermediate_key['keyExpiration'].to_i <= cur_millis
    end
  end
end
