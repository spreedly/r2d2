require "test_helper"

class R2D2::GooglePaymentTokenTest < Minitest::Test

  def setup
    @fixtures = File.dirname(__FILE__) + "/fixtures/google/"
    @tokenized_card = JSON.parse(File.read(@fixtures + "tokenized_card.json"))
    @private_key = File.read(@fixtures + "private_key.pem")
    @payment_token = R2D2::GooglePaymentToken.new(@tokenized_card)
  end

  def test_initialize
    signed_attrs = JSON.parse(@tokenized_card['signedMessage'])
    assert_equal signed_attrs["ephemeralPublicKey"], @payment_token.ephemeral_public_key
    assert_equal signed_attrs["tag"], @payment_token.tag
    assert_equal signed_attrs["encryptedMessage"], @payment_token.encrypted_message
  end

  def test_initialize_unknown_protocol_version
    @tokenized_card['protocolVersion'] = 'foo'

    assert_raises ArgumentError, 'unknown protocolVersion foo' do
      R2D2::GooglePaymentToken.new(@tokenized_card)
    end
  end

  def test_payment_details_from_decrypted_data
    decrypted_attrs = @payment_token.decrypt(@private_key)

    assert_equal "4895370012003478", decrypted_attrs["dpan"]
    assert_equal 12, decrypted_attrs["expirationMonth"]
    assert_equal 2022, decrypted_attrs["expirationYear"]
    assert_equal "3DS", decrypted_attrs["authMethod"]
    assert_equal "AgAAAAAABk4DWZ4C28yUQAAAAAA=", decrypted_attrs["3dsCryptogram"]
    assert_equal "07", decrypted_attrs["3dsEciIndicator"]
  end

  def test_unsupported_payment_method
    @card = JSON.parse(File.read(@fixtures + "card.json"))
    @payment_token = R2D2::GooglePaymentToken.new(@card)

    assert_raises ArgumentError, 'unknown paymentMethod CARD' do
      @payment_token.decrypt(@private_key)
    end
  end
end
