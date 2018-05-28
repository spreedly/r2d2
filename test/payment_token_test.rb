require "test_helper"

class R2D2::PaymentTokenTest < Minitest::Test
  def setup
    fixtures = File.dirname(__FILE__) + "/fixtures/"
    @token_attrs = JSON.parse(File.read(fixtures + "token.json"))
    @private_key = File.read(fixtures + "private_key.pem")
    @payment_token = R2D2::PaymentToken.new(@token_attrs)
  end

  def test_initialize
    assert_equal @token_attrs["ephemeralPublicKey"], @payment_token.ephemeral_public_key
    assert_equal @token_attrs["tag"], @payment_token.tag
    assert_equal @token_attrs["encryptedMessage"], @payment_token.encrypted_message
  end

  def test_successful_decrypt
    payment_data = JSON.parse(@payment_token.decrypt(@private_key))
    assert_equal "4895370012003478", payment_data["dpan"]
    assert_equal 12, payment_data["expirationMonth"]
    assert_equal 2020, payment_data["expirationYear"]
    assert_equal "3DS", payment_data["authMethod"]
    assert_equal "AgAAAAAABk4DWZ4C28yUQAAAAAA=", payment_data["3dsCryptogram"]
    assert_equal "07", payment_data["3dsEciIndicator"]
  end

  def test_invalid_tag
    @payment_token.tag = "SomethingBogus"
    assert_raises R2D2::TagVerificationError do
      JSON.parse(@payment_token.decrypt(@private_key))
    end
  end
end
