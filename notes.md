2.2.  Step 1: Extract

   HKDF-Extract(salt, IKM) -> PRK

   Options:
      Hash     a hash function; HashLen denotes the length of the
               hash function output in octets

   Inputs:
      salt     optional salt value (a non-secret random value);
               if not provided, it is set to a string of HashLen zeros.
      IKM      input keying material

   Output:
      PRK      a pseudorandom key (of HashLen octets)

   The output PRK is calculated as follows:

   PRK = HMAC-Hash(salt, IKM)

2.3.  Step 2: Expand

   HKDF-Expand(PRK, info, L) -> OKM

   Options:
      Hash     a hash function; HashLen denotes the length of the
               hash function output in octets







Krawczyk & Eronen             Informational                     [Page 3]

RFC 5869                 Extract-and-Expand HKDF                May 2010


   Inputs:
      PRK      a pseudorandom key of at least HashLen octets
               (usually, the output from the extract step)
      info     optional context and application specific information
               (can be a zero-length string)
      L        length of output keying material in octets
               (<= 255*HashLen)

   Output:
      OKM      output keying material (of L octets)

   The output OKM is calculated as follows:

   N = ceil(L/HashLen)
   T = T(1) | T(2) | T(3) | ... | T(N)
   OKM = first L octets of T

   where:
   T(0) = empty string (zero length)
   T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
   T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
   T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
   ...

   (where the constant concatenated to the end of each T(n) is a
   single octet.)

https://secure.helpscout.net/conversation/140021416/8693/?folderId=120068

### Problems generating and viewing the keys

For some reason, copy paste doesn't work quite right.  Even pasting to sublime shows that the characters appear the same but don't always work.  May want to always type in the commands.


### How I generated the merchantkey.pem

`openssl ecparam -name 'prime256v1' -genkey -noout -out merchant­_key.pem`

### How I viewed the merchant-key.pem

` openssl ec -in merchant­key.pem -pubout -text -noout`

read EC key
Private-Key: (256 bit)
priv:
    78:ef:55:e3:3d:ad:36:4e:ff:fa:3b:1f:b2:5e:54:
    5b:9c:fd:8e:b9:9c:5f:31:0f:77:d6:b2:21:5c:b5:
    5a:62
pub:
    04:41:b6:0a:7e:bc:8d:8e:67:4f:03:04:1a:7e:ad:
    e4:35:67:2c:a4:6d:3d:29:bf:27:88:b3:11:5d:1d:
    0c:da:7b:9f:ba:15:fd:73:d8:f4:9d:06:fb:10:0c:
    31:a5:65:95:a2:10:7a:5c:53:08:95:1e:99:09:36:
    a2:5e:89:04:3f
ASN1 OID: prime256v1

Then:

cat <<EOF | xxd -r -p | base64
    04:41:b6:0a:7e:bc:8d:8e:67:4f:03:04:1a:7e:ad:
    e4:35:67:2c:a4:6d:3d:29:bf:27:88:b3:11:5d:1d:
    0c:da:7b:9f:ba:15:fd:73:d8:f4:9d:06:fb:10:0c:
    31:a5:65:95:a2:10:7a:5c:53:08:95:1e:99:09:36:
    a2:5e:89:04:3f
EOF

Result:

BEG2Cn68jY5nTwMEGn6t5DVnLKRtPSm/J4izEV0dDNp7n7oV/XPY9J0G+xAMMaVllaIQelxTCJUemQk2ol6JBD8=

cat <<EOF | xxd -r -p | base64
    04:41:b6:0a:7e:bc:8d:8e:67:4f:03:04:1a:7e:ad:
    e4:35:67:2c:a4:6d:3d:29:bf:27:88:b3:11:5d:1d:
    0c:da:7b:9f:ba:15:fd:73:d8:f4:9d:06:fb:10:0c:
    31:a5:65:95:a2:10:7a:5c:53:08:95:1e:99:09:36:
    a2:5e:89:04:3f
EOF

 echo BEG2Cn68jY5nTwMEGn6t5DVnLKRtPSm/J4izEV0dDNp7n7oV/XPY9J0G+xAMMaVllaIQelxTCJUemQk2ol6JBD8= | base64 --decode | xxd -p > testfile.txt

> ECIES a Diffie-Hellman based integrated scheme that combines a Key
> Encapsulation Mechanism (KEM) with a Data Encapsulation Mechanism
> (DEM). The output is a 3-tuple {K,C,T}, where K is a "encrypted shared
> secret" (lots of hand waiving), C is the cipher text and T is an
> authentication tag. In ECIES, K is really half of a ECDHE exchange
> with an ephemeral key. To recover the "encrypted shared secret", the
> person doing the decryption uses their long term static key to perform
> the other half of the key exchange, and that's the shared secret. The
> shared secret is then digested with a KDF and used to key a stream
> cipher and a HMAC.


{
"data": "V65NNwqzK0A1bi0F96HQZr4eFA8fWCatwykv3sFA8Cg4Wn4Ylk/szN6GiFTuYQFrHA7a/h0P3tfEQd09bor6pRqrM8/Bt12R0SHKtnQxbYxTjpMr/7C3Um79n0jseaPlK8+CHXljbYifwGB+cEFh/smP8IO1iw3TL/192HesutfVMKm9zpo5mLNzQ2GMU4JWUGIgrzsew6S6XshelrjE",
"ephemeralPublicKey": "BB9cOXHgf3KcY8dbsU6fhzqTJm3JFvzD+8wcWg0W9r+Xl5gYjoZRxHuYocAx3g82v2o0Le1E2w4sDDl5w3C0lmY=",
"tag": "boJLmOxDduTV5a34CO2IRbgxUjZ9WmfzxNl1lWqQ+Z0="
}

Most promising doc yet https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman

{
"share_secret_bytes" :"[B@4e2c95ee",
"shared_secret_hex" : "611DA6DF50FFDB5ECCDEA5A53C1980499316E7654FEFB4CEB33ADFF711CD00AA"
}

encryptionKey
[16, 79, 44, -105, -90, -108, -104, -111, 8, 18, -18, -101, 121, 100, -109, 98]
104F2C97A69498910812EE9B79649362
macKey
[-28, -1, 49, -64, 121, -124, -9, 98, -89, 11, -22, 96, -37, -118, -47, 28]
E4FF31C07984F762A70BEA60DB8AD11C

sharedKey
[16, 79, 44, -105, -90, -108, -104, -111, 8, 18, -18, -101, 121, 100, -109, 98, -28, -1, 49, -64, 121, -124, -9, 98, -89, 11, -22, 96, -37, -118, -47, 28]
104F2C97A69498910812EE9B79649362E4FF31C07984F762A70BEA60DB8AD11C