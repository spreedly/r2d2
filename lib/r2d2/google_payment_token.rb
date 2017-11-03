module R2D2
  class GooglePaymentToken < PaymentToken
    def initialize(token_attrs)
      version = token_attrs['protocolVersion']
      raise ArgumentError, "unknown protocolVersion #{version}" unless version == 'ECv1'

      signed_message = JSON.parse(token_attrs['signedMessage'])
      super(signed_message)
    end

    def decrypt(private_key_pem)
      message = super

      payment_method = message['paymentMethod']
      raise ArgumentError, "unknown paymentMethod #{payment_method}" unless payment_method == 'TOKENIZED_CARD'

      message['paymentMethodDetails']
    end

    class << self
      def derive_hkdf_keys(ephemeral_public_key, shared_secret, info = 'Google')
        super
      end
    end
  end
end
