require "test_helper"

module R2D2
  class GooglePayTokenTestV2 < Minitest::Test

    def setup
      @recipient_id = '12345678901234567890'
      @fixtures = __dir__ + "/fixtures/"
      @token = JSON.parse(File.read(@fixtures + "ec_v2/tokenized_card.json"))
      @private_key = File.read(@fixtures + "google_pay_token_private_key.pem")
      @verification_keys = JSON.parse(File.read(@fixtures + "verification_keys/google_verification_key_test.json"))
      Timecop.freeze(Time.at(1595000067))
    end

    def teardown
      Timecop.return
    end

    def test_decrypted_tokenized_card
      expected = {
        "messageExpiration" => "1595616845229",
        "messageId" => "AH2EjtffDAl2Jrk2579gUyuaF3ensj4NlaHbyEvOQWtj9IrQNdqJYHl7Vun2kGyFZbuebyKwpDP8fxtSJi-vPIDYbtGwM13_-8o7dBHg74WbXMIwSvW__pCnwmpWn2tFK4PbZ77wRKMh",
        "paymentMethod" => "CARD",
        "paymentMethodDetails" => {
          "expirationYear" => 2025,
          "expirationMonth" => 12,
          "pan" => "4895370012003478",
          "authMethod" => "CRYPTOGRAM_3DS",
          "eciIndicator" => "07",
          "cryptogram" => "AgAAAAAABk4DWZ4C28yUQAAAAAA="
        }
      }
      decrypted = new_token.decrypt(@private_key)

      assert_equal expected, decrypted
    end

    def test_wrong_signature
      @token['signature'] = "MEQCIDxBoUCoFRGReLdZ/cABlSSRIKoOEFoU3e27c14vMZtfAiBtX3pGMEpnw6mSAbnagCCgHlCk3NcFwWYEyxIE6KGZVA\u003d\u003d"

      assert_raises R2D2::SignatureInvalidError do
        new_token.decrypt(@private_key)
      end
    end

    def test_invalid_intermediate_signing_key
      @token['intermediateSigningKey']['signatures'] = ["MEQCIDxBoUCoFRGReLdZ/cABlSSRIKoOEFoU3e27c14vMZtfAiBtX3pGMEpnw6mSAbnagCCgHlCk3NcFwWYEyxIE6KGZVA\u003d\u003d"]

      assert_raises R2D2::SignatureInvalidError do
        new_token.decrypt(@private_key)
      end
    end

    def test_wrong_verification_key
      @verification_keys = JSON.parse(File.read(@fixtures + "verification_keys/google_verification_key_production.json"))

      assert_raises R2D2::SignatureInvalidError do
        new_token.decrypt(@private_key)
      end
    end

    def test_unknown_verification_key_version
      @verification_keys = JSON.parse(File.read(@fixtures + "verification_keys/bad_google_verification_key_test.json"))

      assert_raises R2D2::SignatureInvalidError do
        new_token.decrypt(@private_key)
      end
    end

    def test_expired_message
      ## decryptped_token["messageExpiration"]=>"1595616845229"
      Timecop.freeze(Time.at(1595616846)) do
        assert_raises R2D2::MessageExpiredError do
          new_token.decrypt(@private_key)
        end
      end
    end

    def test_intermediate_key_expired
      ### token["intermediateSigningKey"]["signedKey"]["keyExpiration"] => "1595702501149"
      Timecop.freeze(Time.at(1595702502)) do
        assert_raises R2D2::SignatureInvalidError do
          new_token.decrypt(@private_key)
        end
      end
    end

    private

    def new_token
      R2D2::GooglePayToken.new(
        @token,
        recipient_id: @recipient_id,
        verification_keys: @verification_keys
      )
    end
  end
end
