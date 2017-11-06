require "test_helper"

class R2D2::GooglePaymentTokenTest < Minitest::Test

  def setup
    @merchant_id = '12345678901234567890'
    @fixtures = File.dirname(__FILE__) + "/fixtures/google/"
    @tokenized_card = JSON.parse(File.read(@fixtures + "tokenized_card.json"))
    @private_key = File.read(@fixtures + "private_key.pem")
    @verification_keys = JSON.parse(File.read(@fixtures + "google_verification_key_test.json"))
  end

  def test_initialize_unknown_protocol_version
    @tokenized_card['protocolVersion'] = 'foo'

    assert_raises ArgumentError, 'unknown protocolVersion foo' do
      payment_token
    end
  end

  def test_payment_details_from_decrypted_data
    decrypted_attrs = payment_token.decrypt(@private_key)

    assert_equal "4895370012003478", decrypted_attrs["dpan"]
    assert_equal 12, decrypted_attrs["expirationMonth"]
    assert_equal 2022, decrypted_attrs["expirationYear"]
    assert_equal "3DS", decrypted_attrs["authMethod"]
    assert_equal "AgAAAAAABk4DWZ4C28yUQAAAAAA=", decrypted_attrs["3dsCryptogram"]
    assert_equal "07", decrypted_attrs["3dsEciIndicator"]
  end

  def test_to_length_value
    expected = "\x06\x00\x00\x00Google\x04\x00\x00\x00ECv1\x13\x01\x00\x00" + 'longstring-' * 25
    assert_equal expected, R2D2::GooglePaymentToken.to_length_value('Google', 'ECv1', 'longstring-' * 25)
  end

  def test_wrong_signature
    @tokenized_card['signature'] = "MEQCIDxBoUCoFRGReLdZ/cABlSSRIKoOEFoU3e27c14vMZtfAiBtX3pGMEpnw6mSAbnagCCgHlCk3NcFwWYEyxIE6KGZVA\u003d\u003d"

    assert_raises R2D2::GooglePaymentToken::SignatureInvalidError do
      payment_token.decrypt(@private_key)
    end
  end

  def test_wrong_verification_key
    @verification_keys = JSON.parse(File.read(@fixtures + "google_verification_key_production.json"))

    assert_raises R2D2::GooglePaymentToken::SignatureInvalidError do
      payment_token.decrypt(@private_key)
    end
  end

  def test_unknown_verification_key_version
    @verification_keys['keys'][0]['protocolVersion'] = 'foo'

    assert_raises R2D2::GooglePaymentToken::SignatureInvalidError do
      payment_token.decrypt(@private_key)
    end
  end

  def test_multiple_verification_keys
    production_keys = JSON.parse(File.read(@fixtures + "google_verification_key_production.json"))['keys']
    @verification_keys = { 'keys' => production_keys + @verification_keys['keys'] }

    assert payment_token.decrypt(@private_key)
  end

  def test_unsupported_payment_method
    @tokenized_card = JSON.parse(File.read(@fixtures + "card.json"))

    assert_raises ArgumentError, 'unknown paymentMethod CARD' do
      payment_token.decrypt(@private_key)
    end
  end

  private

  def payment_token
    R2D2::GooglePaymentToken.new(
      @tokenized_card,
      merchant_id: @merchant_id,
      verification_keys: @verification_keys
    )
  end
end
