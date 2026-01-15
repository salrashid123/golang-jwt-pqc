# golang-jwt for post quantum cryptography

Extension for [go-jwt](https://github.com/golang-jwt/jwt#extensions) that allows creating and verifying JWT tokens where the signature schemes uses a set of [post quantum cryptography signature algorithms](https://blog.cloudflare.com/another-look-at-pq-signatures/).

Specifically, this implements jwt signing with `ML-DSA` using both PEM private key files and `Google Cloud KMS` based private keys.` 

A sample JWT generated is in the form:

```json
{
  "alg": "ML-DSA-44",
  "kid": "EMHG0l4cWeRqdIdxtHAYbzoxjLZsyaweF9NMIIDI6hU=",
  "typ": "JWT"
}
{
  "iss": "test",
  "exp": 1739907597
}
```

Note, this library uses cloudflare's implementation.  A TODO is to use upstream go after [issues/64537](https://github.com/golang/go/issues/64537) implements `ML-DSA` and other algorithms (eg `SLH-DSA`)

**critically**, the standards aren't complete yet so this is just a toy and will possibly change.  See draft [Internet X.509 Public Key Infrastructure: Algorithm Identifiers for ML-DSA](https://datatracker.ietf.org/doc/draft-ietf-lamps-dilithium-certificates/)

>> This code is NOT supported by google

---

* [Supported Algorithms](#supported-algorithms)
* [Usage](#usage)
  * [With Private Key Files](#with-private-key-files)
  * [With Google KMS](#with-google-cloud-kms)
* [Misc](#misc)
  * [Private Key Formats](#private-key-formats)
    * [Openssl Formats](#openssl-formats)
  * [PEM Key Conversion](#pem-key-conversion)
  * [Parsing and Generating JWK](#parsing-and-generating-jwk)

---

For other references, see:

* [Cloudflare: A look at the latest post-quantum signature standardization candidates](https://blog.cloudflare.com/another-look-at-pq-signatures/)
* [A Long Goodbye to RSA and ECDSA, and Quick Hello to SLH-DSA](https://medium.com/asecuritysite-when-bob-met-alice/a-long-goodbye-to-rsa-and-ecdsa-and-quick-hello-to-slh-dsa-3e53e36a941b)
* [CRYSTALS Cryptographic Suite for Algebraic Lattices](https://pq-crystals.org/dilithium/)
* [Open Quantum Safe](https://openquantumsafe.org/)
* [crypto: post-quantum support roadmap](https://github.com/golang/go/issues/64537)
* [Quantum doomsday planning (2/2): The post-quantum technology landscape](https://www.taurushq.com/blog/quantum-doomsday-planning-2-2-the-post-quantum-technology-landscape/)

* [AEAD encryption using Post Quantum Cryptography (ML-KEM)](https://github.com/salrashid123/go-pqc-wrapping)
* [Python AEAD encryption using Post Quantum Cryptography (ML-KEM)](https://github.com/salrashid123/python_pqc_wrapping)

* [X25519MLKEM768 client server in go](https://github.com/salrashid123/ml-kem-tls-keyexchange)
* [golang-jwt for Trusted Platform Module TPM](https://github.com/salrashid123/golang-jwt-tpm)

---

### Supported Algorithms

* `ML-DSA-44`
* `ML-DSA-65`
* `ML-DSA-87`

TODO:

* `SLH-DSA-SHA2-128s`
* `SLH-DSA-SHAKE-128s`
* `SLH-DSA-SHA2-128f`


Also, the `alg` field is simply one derived from the draft: [ML-DSA for JOSE and COSE](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/) and may change later (since its still draft) and [SLH-DSA for JOSE and COSE](https://datatracker.ietf.org/doc/draft-ietf-cose-sphincs-plus/)

### Usage

There are two ways you can generate a JWT and verify it:

1)  Read the private/public key from file
2)  Read the private key from GCP KMS and the public key from file

If you want a quickstart to using option (1) see the `examples/` folder

#### With Private Key Files

To use this mode, the private key *must* be in the `bare-seed` format.   Openssl allows you to generate keys in multiple formats and the default library (`"github.com/cloudflare/circl`) used in this repo to sign one of those other formats (`seed-only`).

To generate a new key, see the section at the end.  If you just wanted to quickstart with pre-generated keys, see the `example/` folder and run the `example/ml-dsa-44/main.go`

```golang
package main

import (
	jwt "github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"
	circlsigner "github.com/salrashid123/golang-jwt-pqc/circl"  
	"github.com/cloudflare/circl/pki"
)

var ()

func main() {

	// load and initialize the public and private keys
	// private key must be in bare-seed format
	// unmarshall the private key into so we can just extract the 'seed`
 	privKeyPEMBytes, err := os.ReadFile("certs/bare_seed/ml-dsa-44-private.pem")
	pr, err := circlsigner.GetCIRCLPrivateKeyFromBareSeed(privKeyPEMBytes)

	// issue the jwt
	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwtsigner.SigningMethodMLDSA44, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &circlsigner.CIRCL{
			PrivateKey: pr,
		},
	})
	tokenString, err := token.SignedString(keyctx)

	log.Printf("TOKEN: %s\n", tokenString)


	// to verify

	pubKeyPEMBytes, err := os.ReadFile("certs/ml-dsa-44-public.pem")

	pu, err := pki.UnmarshalPEMPublicKey(pubKeyPEMBytes)

	nkeyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{})

	keyFunc, err := jwtsigner.SignerVerfiyKeyfunc(nkeyctx, &jwtsigner.SignerConfig{
		Signer: &circlsigner.CIRCL{
			PublicKey: pu,
		},
	})

	vtoken, err := jwt.Parse(tokenString, keyFunc)

	if vtoken.Valid {
		log.Println("verified with Signer PublicKey")
	}

}
```

The output is a signed JWT

```bash
$ cd examples/

$ go run ml-dsa-44/bare_seed/main.go 

Found  MLDSA-44  in private key
2026/01/14 22:13:40 TOKEN: eyJhbGciOiJNTC1EU0EtNDQiLCJraWQiOiJrZXlpZF8xIiwidHlwIjoiSldUIn0.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNzY4NDQ2ODgwfQ.rTVBAA9jAaaYlBboPoLPtybNk3D6pzzv2D0nFRwrGWhK88wVwo3LZRpUzwWzz0Sjn_Fnrgi3BOW3uoQX6j3HOjUauN4e4JoxSJn0q76pBfnWIu8VKgsPf0gb1d6_gRLouS9E3QInxmnSNi2tg0s4Ewz17NEL4XPR5u7KakVemXrBmafOjRyxuebffchsYYOiYWsv2Yke-JmKaHIVO3idEtuUiULgJL3wp7ObT_eSVOO3_FVQoM2t9u47OjsK8RxMfe8Osj1wu_lR3Z1CnpADw1vIINRKdMQKJj3-Ge4l95upLis8V-TDnJk3Iyoj9E-OGoO_4LeIANFjuPO7VpYdFcUQWU3OAcMeuqIr08DYH6ewBvclZLom54PIVixPi7xoz7YBsNYj89OENuKpSsCuWEV1MT6wZX7Mrqbbx2hE5vP5OPSsFZWJ6_gHzlNV1uvu04Ih-wP1O8rI4J8VpmYhH-DSVgKnCSFS7pMi4ngJdfuO5Zk4S4PshJR2-fekICOK1y3pPKpVs9bRLbVBr7Ig_FmvHX0c8ShNReg2BKMIs70HeKItHNvjiVyISoIempyex9jBeoeXeV86EmXJ90VBwPBYpqBg5xuIJtMZo1ImM_Cu9OvkCMtv_thQE73DuWKRIVZwuelsXah8pVDy9P8uGw9LZlVHTUmt52OEt2OUjT6AiE94pdFbIIKvYHlIAnk80wZIrfhIQLpBkTc-9qHUi0k8CTskKwpLGaCNlhUdgBz4lH95otBsD1fSBRGmO6Q4M8S1I1FVr7f0FGb3QLp2vMp5p1lTZrq-iu_Sk-A9nJLD9h0_e2JvEB2XFc762cdIuenOMWMuZHxFYwp-2CeWNmmPPHDz5L4JSTahqZtOFGUUW0FGMdnti0JHq0ZjXC1Ojtmtuaw-WOILOfrpAbrFkaD70DHMOp6vEalrWkEiP_sRR5aK6iUIQsFO6WocbECs-PkvxgF8RY3ByPgNcoWxU7HnQ9troW8SkpXj04GDr1bYvYK2PVxMRYxWTwnwGVxJX_5rt8ZfMDAGtOe0ar7yv9TnY00pTM4B_germoQ8Iu7Mf0e3CXohCND8SDlycxjkbIyeSg973tmZ9guyX8csiLFipok6yHIpJHVin7RheX_83tnFLQJKXBkIHBXTiahrrHJxMd2UNSyCNNyePI6V3UqZefuW0MRdh2kPjhXsjYg4lGYPsu_ILbpQDwGLx84klj4iQFAnPKpE5Y3qX6M4Bq-Hq4oHM7NAXjaN2K8xqUmwonUSTw32i6a_8ZxDQzR-p4V2O1lDQfinCT3wH2C9XrNgW1oWPWTbhkfDIotRzD4YpDBIjyvlxTtxpuWd7ig83-iUcP75nyFXfzVud9fDcCaVK4H2M6b0L3tSuRrq-4KkpthaVBn9FkpHBy4D0lyx6JqJ8HSBcM7tZhS4rFRa3tSkKz1HpI_0DnZEyVXyl7KYs18l5TJy2Wnus_tuZSXHgW8O_rom2k7cXGo_Q8xtOyBxuRn8WMlCLXfjfYuUns3Td9xjT3348P8mv0xNEn6UKLYAoU45dUX90E6XX3E37-KMSfyJeihXRAv-fwQiRqGWlMTL2FJ-PRSC1KVKRnnr6OAKuHQat1uGepmuQVDgYYqfWSP_xC9UUUGTjxMbUrO5N6O2gthMNmL9Jbw8JtOd6MHRb2wGfQEIE4qW5_vawMmgbZW_Ik0850fpqML88WzMFyDR5b9u8keRhmCxIAiaDi8SH0iU2Helgw4fuSPpQcOmNU7ire3-f6lYVmcmjF5ZDzskDWMqhFNNu6gK4XP3SENIKOk9oYFAouYSL7g3CbvVoJNOuzJcFsnd1K-5RbCIXzibESksuGX_6k803-YKwAdDuR0lRQQlNRy1tf8poSejMCSDTjgaIRozIFILbc5WV_TEm2BUxjJvSLRQDuWkHnqAuSdtdDm-4UVfz44M6-dLFQ1OoS_gFmAQQ7SfIvw_TwujPA6hZmL4OjnVbUqO7pzYXwYvM19Z6pUTRpapGph7d3cziraaVSQ6l_VMPwmub4xjSjrx4Gauvyjujs3e6UwFsZvVAY8NI_FGDJWpXKtbwBPLL2HA6YHMl0z30UjXZOgo9guusKZGbl43weAN5vC98ra87yCSC-mg-5ZX92a59FhxsW_l7IsDNQ7u_GsCNScJQHF4aKNEk095nYjNjGzGIA1PhBuyquTTJNxlF3d-3E9sPno51iipBl3xE2liPRGa1iUkh6dkqlwuko8PYfbE_2bXWEtWEFm7epJzv-CbK67iZZPS5ZVlBQ1_-7WAOKA7gfDHWT2R9rQlLEeLv5noPVo8KuA2Mt9euA9xvIGLYlG-AwJBCy6FwLqerv6_bYmjL4wBJrswzQGZRpBVbCU5eEZbKMUIZ6OkxkXIVVG7S--5JDaUJ_617GnkB1gBgd8Grm4RYHrRInFcSOqD33m04zRjV_kmP9MGvqMPwufYqe4M3fCZai4yO_BAtDWJGHCELQ-E7z33FPcRCdGYpjC56o8us1hrxyGJZBWNuSPM6koFI-Z35VxcVayICwgHHBGcVa7nQr4MRahWtqljdyLlWOKDMYRrHMZFwqAjAjsz6qsul7po9KWSOZqeE3FBzHiu3FeeLuo4MouFvKoofdxfwIcfskPe-HzntvBy2Jj1hU1I2mdV0Yowy5S28Iiphe9GyDNvY_t7gFZ02-420F0zav2EQLgZTQzGZGdKHKIcP7aaErV4SuH-yUfbEnTTLZH86A-F4wFEBLSia59Juwo_8Fy7wGku5CtN-m3Pad7YtAlOJy10WdUcenxRwLFpVW7LzXmAmKIUgRpMzq6HU9jrUV8a6GEWTRQ9whvtkyPFkIbePktJUkqjDm4phqR8MBFWa9Ps4pHND1KfhHatEcCySeOXu0oP3SP5nCi-lamAUj6CuccbFnJ_U0c_SYi0HDNjoaPqo1Y6Xi64On0q5rHnXVn4R_nHcKBQQlRWZV3bEWbqqxnzoPNNR8DTCOqPut3Wyk2q-XhJVKGfElFJPzRulvrXkK-2qdTUwtIfAFMyJFsxExlbwEsYkhTgrUQla1IyRuQeFQYp04exDz_ZAzYPltWXiKo6Clm_g3JtBTqbOyeqkulIO5-RRX4OHqwSITg8V3mFpMjO0tPi5ekNEBQmK2doe4iKmKCnqKnF1d3l6vcQHio1TLCyx8nhDxMiLi85Ok9VXF6MkJKWz-3y9wAAAAAAAAAAAAAAAAAAAA8kLkE
2026/01/14 22:13:40 verified with Signer PublicKey
2026/01/14 22:13:40 verified with PubicKey
2026/01/14 22:13:40 verified with JWK KeyFunc URL
```


#### With Google Cloud KMS

GCP KMS allows for certain PQC signatures and the following snippet will generate one and then use it to sign/verify in golang and openssl.

See:
* [GCP KMS PQC signing algorithms](https://cloud.google.com/kms/docs/algorithms#pqc_signing_algorithms)

```bash
export GCLOUD_USER=`gcloud config get-value core/account`
export PROJECT_ID=`gcloud config get-value core/project`

gcloud kms keys create mldsa1 --keyring=tkr1 \
   --location=us-central1 --purpose=asymmetric-signing    --default-algorithm=pq-sign-ml-dsa-65

gcloud kms keys add-iam-policy-binding mldsa1  \
        --keyring=tkr1 --location=us-central1  \
        --member=user:$GCLOUD_USER  --role=roles/cloudkms.signer

gcloud kms keys add-iam-policy-binding mldsa1 \
        --keyring=tkr1 --location=us-central1  \
        --member=user:$GCLOUD_USER  --role=roles/cloudkms.viewer

$ gcloud kms keys list --keyring=tkr1 --location=us-central1

NAME                                                                      PURPOSE          ALGORITHM                   PROTECTION_LEVEL  LABELS  PRIMARY_ID  PRIMARY_STATE
projects/core-eso/locations/us-central1/keyRings/tkr1/cryptoKeys/mldsa1   ASYMMETRIC_SIGN  PQ_SIGN_ML_DSA_65           SOFTWARE

echo -n "foo" > certs/plain.txt

## to sign
gcloud kms asymmetric-sign \
    --version 1 \
    --key mldsa1 \
    --keyring tkr1 \
    --location us-central1 \
    --input-file certs/plain.txt \
    --signature-file certs/signed.bin

## to recall the public key as b64 standard nist-pqc format
gcloud kms keys versions get-public-key 1  \
  --key=mldsa1 --keyring=tkr1   --location=us-central1 \
   --public-key-format=nist-pqc
```

To use golang and gcp kms to sign/verify, run

```bash
# to use your must bootstrap application default credentials with access to the kms key
# gcloud auth application-default login
# export GOOGLE_APPLICATION_CREDENTIALS=/path/to/svc-account.json
go run main.go
```


### Misc

#### Private Key formats

As mentioned, this repo only supports the `bare-seed` format.  I'm using that format for future compatiblity

* [OpenSSL Position and Plans on Private Key Formats for the ML-KEM and ML-DSA Post-quantum (PQ) Algorithms](https://openssl-library.org/post/2025-01-21-blog-positionandplans/)
* [Let’s All Agree to Use Seeds as ML-KEM Keys](https://words.filippo.io/ml-kem-seeds/)


##### openssl formats

Note that when you generate a private 
for `ml-dsa-65` using openssl, it defaults to a `seed-priv` custom mode described in[ml_dsa_codecs.c](https://github.com/openssl/openssl/blob/master/providers/implementations/encode_decode/ml_dsa_codecs.c#L160C1-L160C72):

Each mode has a prefix value encoded in the pem along with other data.  However, all we need is the `bare-seed` format and nothing else 

see

```cpp
static const ML_COMMON_PKCS8_FMT ml_dsa_65_p8fmt[NUM_PKCS8_FORMATS] = {
    {
        "seed-priv",
        0x0fea,
        0,
        0x30820fe6,
        0x0420,
        6,
        0x20,
        0x04820fc0,
        0x2a,
        0x0fc0,
        0,
        0,
    },
    {
        "bare-seed",
        0x0020,
        4,
        0,
        0,
        0,
        0x20,
        0,
        0,
        0,
        0,
        0,
    },	
```

so if you generate an mldsa  key

```bash
## you can use this docker file if your openssl doens't support mldsa yet
### $ docker run -v /dev/urandom:/dev/urandom  -ti salrashid123/openssl-pqs:3.5.0-dev 

## by default openssl generates `seed-priv` fomrat
openssl genpkey -algorithm ML-DSA-65 -out priv-ml-dsa-65-seed-priv.pem

### but what we need is `seed-only`
openssl genpkey -algorithm ML-DSA-65 -provparam ml-dsa.output_formats=bare-seed -out priv-ml-dsa-65-bare-seed.pem
## generates the public key 
openssl pkey -in  priv-ml-dsa-65-bare-seed.pem -pubout -out pub-ml-dsa65.pem

### note the 0x30820a26 prefix
$ openssl asn1parse -in priv-ml-dsa-65-seed-priv.pem
    0:d=0  hl=4 l=4094 cons: SEQUENCE          
    4:d=1  hl=2 l=   1 prim: INTEGER           :00
    7:d=1  hl=2 l=  11 cons: SEQUENCE          
    9:d=2  hl=2 l=   9 prim: OBJECT            :ML-DSA-65
   20:d=1  hl=4 l=4074 prim: OCTET STRING      [HEX DUMP]:30820FE60420B1898E  ### <<< note the 30802FE6 prefix

$ openssl asn1parse -in priv-ml-dsa-65-bare-seed.pem
    0:d=0  hl=2 l=  50 cons: SEQUENCE          
    2:d=1  hl=2 l=   1 prim: INTEGER           :00
    5:d=1  hl=2 l=  11 cons: SEQUENCE          
    7:d=2  hl=2 l=   9 prim: OBJECT            :ML-DSA-65
   18:d=1  hl=2 l=  32 prim: OCTET STRING      [HEX DUMP]:D503DF37166D95B00F35A0B4CD67AEA0DAAD2B449EB1BFFB42934321E3B22C06

### bare seed
$ cat priv-ml-dsa-65-bare-seed.pem
-----BEGIN PRIVATE KEY-----
MDICAQAwCwYJYIZIAWUDBAMSBCDVA983Fm2VsA81oLTNZ66g2q0rRJ6xv/tCk0Mh
47IsBg==
-----END PRIVATE KEY-----

### to display the contents of the `seed-priv` and `bare-seed`

openssl pkey -in priv-ml-dsa-65-bare-seed.pem -text
	ML-DSA-65 Private-Key:
	seed:
		d5:03:df:37:16:6d:95:b0:0f:35:a0:b4:cd:67:ae:
		a0:da:ad:2b:44:9e:b1:bf:fb:42:93:43:21:e3:b2:
		2c:06

openssl pkey -in priv-ml-dsa-65-seed-priv.pem -text
	ML-DSA-65 Private-Key:
	seed:
		b1:89:8e:3b:eb:31:be:18:f6:74:c7:67:5e:18:7e:
		db:ba:25:94:bc:4a:cb:08:a9:69:4a:f6:78:a3:c6:
		cd:e0

### to convert any format to bare-seed
$ openssl pkey -in priv-ml-dsa-65-seed-priv.pem   -provparam ml-dsa.output_formats=bare-seed -out priv-ml-dsa-65-bare-seed.pem

## sign/verify
echo "This is the message to be signed." > /tmp/message.txt

openssl dgst -sign  priv-ml-dsa-65-seed-priv.pem -out /tmp/signature.bin /tmp/message.txt

openssl dgst -verify certs/pub-ml-dsa.pem  -signature /tmp/signature.bin /tmp/message.txt
```

The following will generate a new keypair using go `mldsa` package and write the keys to a file.

Note that we're writing the **seed only** as the private key

to convert with openssl from one format to another use the `-provparam ml-dsa.output_formats=` parameter

```bash
openssl genpkey -algorithm ML-DSA-65 -out priv-ml-dsa-65-seed-priv.pem

openssl pkey -in  priv-ml-dsa-65-seed-priv.pem   -provparam ml-dsa.output_formats=bare-seed -out  priv-ml-dsa-65-bare-seed.pem
```

##### CIRCL format

The default library i'm using here  is * `"github.com/cloudflare/circl/sign/mldsa/mldsa65"` which itself uses the `seed-only` format and a header tag for the PEM format.

eg, given the prefix `0x8020`

```cpp
    {
        "seed-only",
        0x0022,
        2,
        0x8020,  <<<<<<<
        0,
        2,
        0x20,
        0,
        0,
        0,
        0,
        0,
    },
```

if you generate a key, it will look like

```bash
-----BEGIN ML-DSA-65 PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMSBCKAIFJzUWfjlrlWwutVniJIvGkIMC1FCI4ZX2RV
Ao4BN3J3
-----END ML-DSA-65 PRIVATE KEY-----
```


which if you decode
```bash

$ docker run -v /dev/urandom:/dev/urandom -v `pwd`/certs:/apps/certs  -ti salrashid123/openssl-pqs:3.5.0-dev 

### note the 8020 prefix
$ openssl asn1parse -in certs/priv-ml-dsa.pem 
    0:d=0  hl=2 l=  52 cons: SEQUENCE          
    2:d=1  hl=2 l=   1 prim: INTEGER           :00
    5:d=1  hl=2 l=  11 cons: SEQUENCE          
    7:d=2  hl=2 l=   9 prim: OBJECT            :ML-DSA-65
   18:d=1  hl=2 l=  34 prim: OCTET STRING      [HEX DUMP]:802052735167E396B956C2EB559E2248BC6908302D45088E195F6455028E01377277
```

To make this compatible with this library, you'll need to


1. remove `ML-DSA-65` in the PEM formatted preamble
2. convert it to `bare-seed`

```bash
## remove ML-DSA-65
$ cat certs/priv-ml-dsa.pem 
-----BEGIN ML-DSA-65 PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMSBCKAIFJzUWfjlrlWwutVniJIvGkIMC1FCI4ZX2RV
Ao4BN3J3
-----END ML-DSA-65 PRIVATE KEY-----

### to get

$ cat certs/priv-ml-dsa-raw.pem 
-----BEGIN PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMSBCKAIFJzUWfjlrlWwutVniJIvGkIMC1FCI4ZX2RV
Ao4BN3J3
-----END PRIVATE KEY-----

### to convert to bare-seed
openssl pkey -in certs/priv-ml-dsa-raw.pem   -provparam ml-dsa.output_formats=bare-seed -out certs/priv-ml-dsa-bare-seed.pem
```

The example in [example/genkey/mldsa/main.go](example/genkey/mldsa/main.go) does all of that for a new key:

```bash
$ go run genkey/mldsa/main.go 

Public : 
-----BEGIN PUBLIC KEY-----
MIIFMjALBglghkgBZQMEAxEDggUhALPLQzZA/5QxbSA9hFAC1qHiOSgdVUdnrlte
N38UEurvq8zWukzYEqfsrmnoYpDZIsJFURbvAZ/BsnOcbUxwBbhEwt2jfSSQi4OB
W5LP2Vsnz6iqpOHsXCd/kP0Nw1ZUr6oe4MxabqW1B6tAr+2MPCTbs/Gvvip/viOZ
wBkyxkYorQkRiKd3MxN/ja+0uIZXaN/5c74kFrSeE7QSb8AKr5UYp0A8gdUAMnpz
sHB5qY3KMZ0NAnQoi+n5eY/3RMOxnbQMuaVelEyk11UrdzU6LzVnOW8vZ9495bBP
ECCBcOmdQmmeVtaaq12Z+bDV5LOC13TvCu4BK5VrxNtI35AMLMZAPrj9vTZlVqAA
yHQiskcnImvakYnv2viTdU7gYkMQMww6CawY0nFjWe4Up/zMtWonybkViRR063IJ
1reMMTIbBno7l4h97gMIfYFAv+Hl/jY42fGvjBxQOWN/9pUhgUoFWWuGfSwN0oRj
Ls2b/KqbfsMfXWihXcp/G1Iv2b1crS+/+VCkpFc2v7v6FR5OSo2OVf20IZIhQBD0
AyiiSjh5FQFyN9J5OtHChiIoOMFl74l90HlVe2UC3FQikPZlGL69aduo1woc/+L+
Wc5VfxuzE9EIQDNglsstm2aooHb1hAzzxdyqwu3rQiL+Nv2gdvo1Djikw92BVYZD
4mieJ3eBu9Wt4OPpDKm18P+5MuiQSbaOrK9fGGwRiki6/ivCLUlgEzVKy49hlSKD
0pXpTapprvAtYRIOtWTz5goIdbtH94IqsIdq51lsexUV/9UuXa0Us4dvqN1yMf34
UTLOEnplPYYtxNzFGVnkVTbwuq5hAk/Olf48pDXWo7x5JhnaAYsEsActc9CZHwqo
tI3JqULvynKW3orpDteJMQXQ6Wwh5w6+tiH+ZaYwliVFTH1MbuU8m+h3UauxMx71
JleEOF5gG9HqI/kVryVou/oXmCXpB+NEaJTrCRC5UTlrImByO20qSopOykmiJUfK
ivtONmYRYtAUlbdkbd7aA5FB0clZ3VsSFovjJrLRiGY+kiz9tXa87oSt0ih2IOIC
Ds8+BgCic9s87PuknrUkdYxNxpFCx2V3yh7Slh0Pw2ylPuXUCTUHW49hB6JcoQM3
9KyfscVDUmCOiG2HhiP8yH19buEOvq4mnH/TAKYlE6uaU+ErT1KjHMFs5hseRX6u
G24k9+t3S4m9f9O6pgF8UelB/0G8hiuv4zt+crSUWnXyozLk9ASlBaYPCXvGtR+h
dYvStoKyQi+tKCnO6+sOEfMxW9A0SuXLQbd76FB8phBWVick/HOa7aN9lnGJGKYt
osRTVflWAw2W1zVlg0khGqlABVrwBjZyaYU69tMcZI4rW4pYgydGB1AYg5OPYDjV
3kWJ7zyfPR6/G+8Y6J1rS2Dd7cZPOJiDwR3gMleCfZhIHxQpknUeQvqbqkFbOR4+
N3KuL2IP7waz0v4VJZJC7m9HPWgP5hA0tGQ6UQVoWetHndwyGS0ytribPmNrRlqo
ebVqjNqUWMPbpChG5gaCRZEDTJh8bQZ+Ki0WQTtLehqHeNPooyYmeVSKqnVb8IPQ
ea/gn8z4A6+4LSh101sdY6kWt82gy7fe4+Z1bumtgZcouagB2Rwk3nn/MXeY2qwS
oSZ8pRzbqjQLnxROhp1dqaqHSTLWWrD8cVIa/EDJAdWbwkpVxUguklnUtBHIrp85
QVW4zp7HPu16qyJTcTIQ7VtWDV2NUO1Gp3TX6PRfG7NqT9a6qQQ=
-----END PUBLIC KEY-----

Private  in seed-only format: 
-----BEGIN ML-DSA-44 PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMRBCKAIPiPveYSQT/E6HEAMIBRtWXS+gTWoHbKW55D
TnBnUGqy
-----END ML-DSA-44 PRIVATE KEY-----

Private  in bare-seed format: 
-----BEGIN PRIVATE KEY-----
AgEAMAsGCWCGSAFlAwQDEQQigCD4j73mEkE/xOhxADCAUbVl0voE1qB2ylueQ05w
Z1Bqsg==
-----END PRIVATE KEY-----
```

#### Parsing and Generating JWK

If you needed to generate a JWK, you can use the `example/jwk/main.go` as a reference.  What that does is generates the JSON representation of any given key.  Note the `pub` field is the raw DER encoded `SubjectPublicKeyInfo` bytes


```json
{
  "keys": [
    {
      "kty": "ML-DSA",
      "kid": "keyid_1",
      "alg": "ML-DSA-44",
      "pub": "TuLJIaUVFnl4Xl/FvfsBmJTSdXLmPX+qD4icxvkBJSjXXZBgba0Gtrk3SIOaBHTQzJFmEl/TWNcXgiZDdXhh0EEANKTfGvm6n+oR5U9AZqYyULGkHdSAnXZ4ocprlmDSl4U1/UlhSvkq9T2o0p1zXO3lk1JxJeV/SGRaU6Hssqhni2onN3aHwiJTySu4sfSorjS9WMfZSv+ujT4fERbb1Z/D4NULBHmfKh7ujRVsyxa3H166VFn8GBIhB1mfpYsvvm1M+oe4rjUtL55Fa7DF66CSMEqmNTLMf6eTLwdPh9ZDwgCNPf/4AZADFGxgOGKVanoV1r1qDkTwmUO71p0JJr+d/nQiV2RcuXlW/2FC7ftlWIOzD7AQOMc2sjptmSPeDerGpJKkyyRNTpD9fqnpT46+Fz6XdjnJnO07ItgHYIJFUUprk/UJVXgvK0smVubBm347UWGSiK3y1nNP6TUOi8AJfTWUZy4muiF7uh+EVHp3GjeL1S5gJTL7DAk6HmJt7r3VXCycS3dEx+0ZMIwsODZHVsp7F/9v82JV7xj7VVhfXZrXNFG7z8SJLYomO1K1pe9JnHFwYJfyVDQ7ngXF5Lw/OH1klzLsxGPibDocKcctbq366DRdiXN7cG7GVRskrqQ9aH56f1yHY/RR65NVfe3z7C38rmwczdQmdeiJmMsvlJ0hltK4gthQ72/YBPBHsPXTmTlIUxCetD5myC2Wu/JqPuwpd4mjcHClpRbWha7XJbdzL09Fl7Y66XSYk9L/2OhB5mYYOZ3HB6clbaY7nsCGuV5qyQOodhv0fx1OaP/FXg52tycc9kgC5RFsF9m0d+SrSiyRfT4wnJDIrtVaC4AD/1arxgstXcRd6sj8A/K1J1lckPuXcoHvBDckGzTI9KZf9ldLABYM4ZNrc5EGSLjPGcwplhJpeMckuRPRO7RyQumQwh7cna2Id7/BKfG2MCQBnSXOB+HCrKXO8WOJEm2vNoSshxATBjAvVENPhjNS7Ah3VALDm6pdKtfPbhdwMFLH8hogJAnq7CQWZt9aeOZ/W5a4tTRQt/yQQkfnSNbyusgpwibeWB0Ul5S7HmxTh32VDuP7MvCVBXki3dOf+J30evuXMdPjOaelD1GZU0xcytVToLiRNk57GNNg42KrkFHKSXcTufwHdzpbT3l5aHcJtWsqRLiBy6pJYTpvF4jhzmIO/rmqPmdIwtod/+cj/DfNZfYmvzp+D29EfWVcMeOqmcBi7DFa0N0zMkZNEauG6UdZmdV+2CwhDmD4aGswxwYD6kHVAvn6dRq0P2rNd7DzOe4/FRymLQyHvcZQwVHvnzl1TZdvMLUo0yEv5YKntiRhcN+v+RRh7xBXbRYLl8oBP3BlBeQQHrLcng9vZDIYYAUpRWS2iif7kMa9ENsZ4jaDjCuYdqn4l/PKP2GjNMpluOHqp94ZpESSQdpQVUrQQcRosGIAseYxS7vd3mHP7ttRTN7RtbiOLVAIDiM2MXMoQnxMN9sHCGdS4xsjeRuV2Hsnd8eHvKmzL2CFJE2dA7OfkgT3psnzHYVYCZ2R4WwZFsXN3nJp/8ztIkLRanhVexs4H7PCXxn2sbJAA2nseFNAY4Ck04z9cFLfxNXJwR39DkV51yxzbq2P9sp8A7QS01wRFt35So+Vq9GJj7nq/mWZndTL1TvfM+4PHXfTuXuqA1GzhQ9e2AK4AcblfKY8dIkHshfREMIh/JDT7dLynyAkgTIP9D6ovaGzfjIyQQ=="
    },
    {
      "kty": "ML-DSA",
      "kid": "keyid_2",
      "alg": "ML-DSA-65",
      "pub": "u42iVchx9qivlSkwM1m0SA9BbE47S/eMh7VX37ycqvyAD56H0B0Pse2QCqtsfts0yHVFtDIzES1jr81l6Gb6aw46rQZq4hWmYe/J71n2MTPJhfRAtYxx7VlLykwxqi5MT3TTAF+JQVY5mIkXks99z2BHHdRztMK3XUoiq8vbxi3d6GpJoaCHb6tZwXqDe1XqTCAVJvp+sROIHzGexcYsgtg77su97p3WdLpItJ1vzhHj2yIbc9UtTwLSid+TWE6nAf67k/kXxRssyFdVV8/5Nlz9JVAowqqT4xa37Qiv729FHCqkF3hO7fhSvU7ZoRA/2AR7ny7ryVfylehHD3TH72Y3qjhn2THwvXAy+bFu98yzCk+HIR3Vcht2uMij76Y/21uZPSYGNiePUKao/iWNA1uu+2QXo1v8JuDobn4hNmN9I+Y29trs2753uVFxKFTv9LztE5q8Qcxd65xkbvsW0DvWULsPuotaTb9m+HqzyK5LMaACcj/pFmJbi912Wb6MNOCsNO0V49QVbK3zjtyRNQF977v+k1u2OKX3x85MxO5yEZlJsXFvCjUmyQlaA42dRWxYf/u7XwDDc/K+y0ZB2+9EzfUdTUwZhvLTnR6P8vSmFuysVgI9lSHtSqJV/wUOeRyY1t44rfempxka2ZJQkZ7phZMZteHvvWed7tKYzuyBdGFIOXiao/bsqC/R7NouGnorKi1HGoyCW9jFgGyAq0vcz26nG1y8maKQFzSskFZT3D8ctyhtptMvOEC0MoWU+TGt0oTTfN+gs5jawIOil/bfSDRjo9YB/98C6S7GuGg38UFR9NEmAD7AXkSK1Hmj5CqwoecrIlAlVBx3zPvTssGk2Qx6dpe4FNEWOubN2LGM7Tr1d9ZZR/jVAFMIFu2DPfzFyHgQEr5+Qg5txi/ARMwFGiRzToOhZ/o+XraQsrkr8Z6JQ3qA0HgPhPtjPDTZ6WMDd/V5WZggKIrZmdqA9/YO6qhy25p2L8+mSS9pzBcQjusTpbrPelSgI5HCJuhQs+KmBGXmSV/DuliG9+CmzgPNwGNUKsEPOtNc1Xg+AFS53vVLAGRuYVHgsCmKhWCc+wJUIB1XsH2WrBIEWNQRC191/CkxXnNwbyg3tBigGYaN5hFf67tMPCsFJlYK72hFhAXVVoKFMgikZlDQPv0L/2PRS9R4NpThDVcZU9/6zptRD8COXEFHpaIdco9K7dHl13USnikdb/Btb582StSv6dPk0ZsT/rY1VhQUssTA3/OOeGDyh5feYsBP9/RLuQkdUVpislArhbifn0AIpQGK75xGnOjSgr4PDVIzCBo0HqTVB4K49syG6m0Ewo+dbAs9rpBjjWWSYwin2APOhKD9kEN/ysztv1EnFhobeQir2Ux62cDio7gP5/8LNkQ7GgblcxGffnXood/Gfxpv3MAN+iqiLdoH6ief9JSSiBwb0UmlHUvgKSzjVAK+Lo4Ef8xPwrUFBshPgsdD8nm0HXElOF003AMoyEZhYT28H5Y/fDyUtRM/d++aN+RigGPpk+jbhk4Sidbi241an3FGrFzcfyzsA9ofk6zYhXzIzNY3EunAS8yvOozXpnHsJ2+ceArGzUKLA+G96rknGghCgI+Uv7uMKNsfhHKHoPk7H+xnFefYCBUfZaVGVenXoWEBBJ/NHhof3eLRHHnbx3tAjX8ybhN+tvZiHstEDD6c+r1ulLJ2OUXKEIt3/03LK38Flb1p8h+T9vrmsUH7tIZ/8CQ+PCXOSzPw8W7WLvRea+W2Ime3Rq36Jd3cWAd4FLuL8ulTQLBe8hI5+OWycM6dVPoCTvkm4vmhhDGgIZl5sK9L1/HWoLdunz7j0Nbafa6Ip0DoxEJT00muL1oThjfvYGPVC33HvcHlLOySqIIIWp8EMW7dpnnQFKWYd2qpm8jSqO3FMbipFvQxwKlOYHRfNdVWO7+XC22Z3VnmFTgkdcmoLoSgp7/842mENhY388zPV90SionboRoKAZw2ROa55yMSwbTwhUrecyFkknwIC37vpEtOdcNFP8eMA5/Ztz7dV52shcD9sSIbZEimlK+acf/1i/Yj5feLaZgs3HVkyTuWDvERVSoFEXZ7lafFsYetocAyWde7qJYridU8dFyG80BMJV9qjYlbXJ4WGLo6bY2ujmDvIIfTZttz4dEw2gqIxQXVGwLJY7YOqvpDBWMuX1in1ucRNfxaFwv6oaMKQhHtgAf5W5CtOihz/sx46sg4lALpPiZVRuqEvXPbEsl8fxCEKXpiGCgbn/6GQvceZ9THQ6nggLcJTkMraqwibWXYPhdbJ4Hw9UoCn8W03rFNav4Z5jsNd25ehl5xTBl2hODi2uj6jdnO5JC7dxjdbgAGIXmYxaukSJO1ycJ6sVT1VxvIvEuSm5M9/5IXbnO1uWquMcyNLplf6KJybRq7A61vGHxqrliOdxA8k8AHcp31L4ZVDGGvNW+N0tFYBb+CJ+9dMyC2AYlDGrrshQXCG01VjXssgdWWaNhAjDgSTSZohi++IiO8A3YeGirSgvUFLMbjsD7Pzv/Ts/wdl+C13HDW5xEdNpdrl55GMfvuoq+4M2zoADsTF1HGGeEqacY3Go2jk7Q="
    },
    {
      "kty": "ML-DSA",
      "kid": "keyid_3",
      "alg": "ML-DSA-87",
      "pub": "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"
    },
    {
      "kty": "ML-DSA",
      "kid": "keyid_4",
      "alg": "ML-DSA-65",
      "pub": "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"
    }    
  ]
}

```
