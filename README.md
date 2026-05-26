# golang-jwt for post quantum cryptography

Extension for [go-jwt](https://github.com/golang-jwt/jwt#extensions) that allows creating and verifying JWT tokens where the signature schemes uses a set of [post quantum cryptography signature algorithms](https://blog.cloudflare.com/another-look-at-pq-signatures/).

Specifically, this implements jwt signing with `ML-DSA` using either

* PEM private key files
* `Google Cloud KMS` 
* `AWS KMS`
* `HashiCorp Vault` (exprimental)

A sample JWT generated is in the form:

```json
{
  "alg": "ML-DSA-44",
  "kty": "AKP",
  "kid": "EMHG0l4cWeRqdIdxtHAYbzoxjLZsyaweF9NMIIDI6hU=",
  "typ": "JWT"
}
{
  "iss": "test",
  "exp": 1739907597
}
```

While MLDSA is [NIST approved](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf), the specific JWT standard is draft

* [ML-DSA for JOSE and COSE](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/)

>> This code is NOT supported by google

---

>> *NOTE* this library internally uses `"filippo.io/mldsa"` as the mlDSA provider which is still under devleopment [https://github.com/golang/go/issues/77626](https://github.com/golang/go/issues/77626).  Eventually when that is merged into standard go  `"crypto/mldsa"`, i'll swap the implementation.  Please note that will be a breaking change since it will migrate the return function parameters from `"filippo.io/mldsa"` --> `crypto/mldsa`.  If you want to see an example with a patched version of upstream golang, see the [go_127](https://github.com/salrashid123/golang-jwt-pqc/tree/go_127) branch in this repo: 

---

* [Supported Algorithms](#supported-algorithms)
* [Usage](#usage)
  * [With Private Key Files](#with-private-key-files)
  * [With Google KMS](#with-google-cloud-kms)
  * [With AWS KMS](#with-aws-kms)
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

* [Json Web Encryption (JWE) using Post Quantum Cryptography (ML-KEM)](https://github.com/salrashid123/jwe-pqc)

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
2)  Use KMS based private key to sign and the public key from file to verify

This library is separted out into several contained modules depending on your usecase.

You'll need to always import the base module `github.com/salrashid123/golang-jwt-pqc`

- If you want to use plain PEM based private keys, you need to import the base module and `github.com/salrashid123/golang-jwt-pqc/mldsa`
- If you want to use GCP KMS, import the base module and `github.com/salrashid123/golang-jwt-pqc/gcpkms`
- If you you want to use AWS KMS, import the base module and `github.com/salrashid123/golang-jwt-pqc/awskms`

see the `examples/` folder.  

For PEM based privatekeys, the minimal sample is:

- `sign`

```golang
import (
	jwt "github.com/golang-jwt/jwt/v5"
	jwtsigner "github.com/salrashid123/golang-jwt-pqc"
	mldsasigner "github.com/salrashid123/golang-jwt-pqc/mldsa"
)

	privKeyPEMBytes, err := os.ReadFile("certs/bare_seed/ml-dsa-44-private.pem")
	privateKey, err := jwtsigner.GetPrivateKeyInfoFromPEM(privKeyPEMBytes)

	claims := &jwt.RegisteredClaims{
		ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Minute * 1)},
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwtsigner.SigningMethodMLDSA44, claims)

	keyctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &mldsasigner.MLDSA{
			PrivateKey: privateKey,
		},
	})

	token.Header["kid"] = "keyid_1"
	token.Header["kty"] = "AKP"  
	tokenString, err := token.SignedString(keyctx)
	fmt.Printf("TOKEN: %s\n", tokenString)
```

- `verify`

```golang
	pubKeyPEMBytes, err := os.ReadFile("certs/ml-dsa-44-public.pem")
	publicKey, err := jwtsigner.GetSubjectPublicKeyInfoFromPEM(pubKeyPEMBytes)

	verifierctx, err := jwtsigner.NewSignerContext(ctx, &jwtsigner.SignerConfig{
		Signer: &mldsasigner.MLDSA{
			PublicKey: publicKey,
		},
	})

	keyFunc, err := jwtsigner.SignerVerfiyKeyfunc(verifierctx)

	vtoken, err := jwt.Parse(tokenString, keyFunc)

	if vtoken.Valid {
		fmt.Println("verified with Signer PublicKey")
	}
```

#### With Private Key Files

To use this mode, the private key *must* be in the `bare-seed` format.   Openssl allows you to generate keys in multiple formats and the default library (`"crypto/mldsa`) used in this repo to sign one of those other formats (`seed-only`).

To generate a new key, see the section at the end.  If you just wanted to quickstart with pre-generated keys, see the `example/` folder and run the `example/ml-dsa-44/main.go`

The output is a signed JWT

```bash
$ cd examples/

$ go run ml-dsa-44/main.go 

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

## to sign
echo -n "foo" > certs/plain.txt
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
go run ml-dsa-65-gcp-kms/main.go \
   --kmsURI="projects/core-eso/locations/us-central1/keyRings/tkr1/cryptoKeys/mldsa1/cryptoKeyVersions/1"
```

#### With AWS KMS

To use [AWS KMS MLDSA](https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html), first setup an MLDSA key and acquire the key-id and region.

In my case, it was:

```bash
$ aws kms describe-key --region=us-east-2 --key-id="37aca4ea-3915-441f-b03d-d90bad1eb45a" 
{
    "KeyMetadata": {
        "AWSAccountId": "291738redacted",
        "KeyId": "37aca4ea-3915-441f-b03d-d90bad1eb45a",
        "Arn": "arn:aws:kms:us-east-2:291738redacted:key/37aca4ea-3915-441f-b03d-d90bad1eb45a",
        "CreationDate": "2026-02-21T06:38:35.013000-05:00",
        "Enabled": true,
        "Description": "",
        "KeyUsage": "SIGN_VERIFY",
        "KeyState": "Enabled",
        "Origin": "AWS_KMS",
        "KeyManager": "CUSTOMER",
        "CustomerMasterKeySpec": "ML_DSA_65",
        "SigningAlgorithms": [
            "ML_DSA_SHAKE_256"
        ]
    }
}
```

you can get the public key using the awsCLI or running `example/ml-dsa-65-aws-kms/main.go`

```bash
aws kms get-public-key --region=us-east-2 --key-id="37aca4ea-3915-441f-b03d-d90bad1eb45a" --output text --query PublicKey > /tmp/PublicKey.b64
openssl enc -d -base64 -A -in /tmp/PublicKey.b64 -out /tmp/PublicKey.der
openssl pkey -inform DER -pubin -in /tmp/PublicKey.der -outform PEM -out certs/ml-dsa-65-public-awskms.pem

### then to run the sample:
$ go run ml-dsa-65-aws-kms/main.go --region=us-east-2 --keyID="37aca4ea-3915-441f-b03d-d90bad1eb45a"
```

### With HashiCorp Vault Enterprise

HashiCorp Vault also support MLDSA but you have to use the "Enterprise" version.

The following demonstrates using the _trial_ Vault Enterprise 


```bash
### first get the root token and vault's address
export VAULT_TOKEN=hvs.CAESIKIBgCMQ_l3sJXdHEwwb6KfR9Q14buCX7bIqwA8YSE4YGicKImh2cy4xUGlHVVhBc2RzQ---redacted
export VAULT_ADDR="https://vault-cluster-public-vault-c305537c.8639af5b.z1.hashicorp.cloud:8200"
export VAULT_NAMESPACE="admin"

## enable the transit engine and create an mldsa-65 key

cd example/
vault secrets enable transit
vault policy write secrets-policy secrets_policy.hcl
vault policy write token-policy token_policy.hcl
vault write -f transit/keys/my-sign-key type=ml-dsa parameter_set=65


$ vault write -f transit/keys/my-sign-key type=ml-dsa parameter_set=65
      Key                       Value
      ---                       -----
      allow_plaintext_backup    false
      auto_rotate_period        0s
      deletion_allowed          false
      derived                   false
      exportable                false
      imported_key              false
      keys                      map[1:map[certificate_chain: creation_time:2026-05-26T14:37:45.456447107Z hybrid_public_key: name:ml-dsa-65 public_key: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]]
      latest_version            1
      min_available_version     0
      min_decryption_version    1
      min_encryption_version    0
      name                      my-sign-key
      parameter_set             65
      supports_decryption       false
      supports_derivation       false
      supports_encryption       false
      supports_signing          true
      type                      ml-dsa


#### now create a "end user" token (i.,e not root)
$ vault token create -policy=token-policy  -policy=secrets-policy

export VAULT_TOKEN=hvs.CAESIC5M9tE29uEq5_ms9-FgbevRmBzxkryS9PURZk0fgmk4GicKImh2cy5obU9LVXF2a052Q3N3R2lGQW5DR---redacted
export VAULT_ADDR="https://vault-cluster-public-vault-c305537c.8639af5b.z1.hashicorp.cloud:8200"
export VAULT_NAMESPACE="admin"

### test signing
PAYLOAD=$(echo -n "Hello, Vault" | base64)
vault write -format=json transit/sign/my-sign-key input="$PAYLOAD"

```

Now use it

```bash
$ go run ml-dsa-65-vault/main.go -namespace admin --keyName=my-sign-key \
   -vault_addr="https://vault-cluster-public-vault-c305537c.8639af5b.z1.hashicorp.cloud:8200" \
   -vault_token="hvs.CAESIC5M9tE29uEq5_ms9-FgbevRmBzxkryS9PURZk0fgmk4GicKImh2cy5obU9LVXF2a052Q3N3R2lGQW5DRE5pY---redacted"
ml-dsa-65
-----BEGIN PUBLIC KEY-----
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
Wqz6ZSsJ
-----END PUBLIC KEY-----
Got Public Key ML-DSA-65
2026/05/26 14:07:21 TOKEN: eyJhbGciOiJNTC1EU0EtNjUiLCJraWQiOiJrZXlpZF81Iiwia3R5IjoiQUtQIiwidHlwIjoiSldUIn0.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNzc5ODE4OTAxfQ.mfQPXteqHdj1CUl2WmaV7EpkVj9ffCbJ2o0S_1ORejz__yWkC23YVSE5yIB6nMqez-PJVkTe3Y2hWLMwg79wW4otk1fvE6Pu4igqI3bH2jBqORZh-BGqZU1LeatNbkVJ0X1LVkqJevshZBSX7rH63UiCDqpejc-culAIicP6XBqw4uglVuZOUj1ayR7ar7FNJEbNLqv2nMaE1MhEkRIH6gH0NExX-m7TUkMDplqZ6MWkhD3xPOUVAUHun0Aq8Q2R5Y5bLQDmxzdb7bcKorAaijfN7FrOFi59w0VVhhi6JiFw9tbU0txdkd58aQkbTW0npslP0xz5zfV45jVRxOvUEF-cUZVzo4ibg5TwBBoApmlmwj5cHNjLFwqySsW339SuN5-c52FFhXVS9CpLqMMHGqW87DBsvIwS6Eyud9fDEiTqadmlReRg0FizpDntgWtkjRKT7a5aoeEt56jFb4CCreOlpL6nkq1fs80fLrMzwYDSGkH8lX5FOcfqgodQPbhcFrrf5W16tZ5GbmH15YhjgE4fjnT-Twh8Gy4KLx0337ztzEXCTHIerCw6ckba25AWzCIkEeNAD6F480xqbjHdgxUEGtdfeVHpjxxoM5vECHKHc--2o_pxr9kMGCOsMXUsQF8RUmZbSAh4MoGikk7UAvxDeVa3XcGmOrVkQWeiE5DLo5O1m1-ajBgjA9CpEUAYQnSBswItNvuwYderkSI2SS2sDlkZjdiFYrgAxcEghSy-6TNChLgGM0T9nJoz55Uv84EV7z4npSalmNzjq5EgNHuQNaP_3upndQ562gpwI4o3etHAU9agYwS7z2hIJMuNOpm_A2MsgseY-f9J2us-zPuOjsBKAsh4FW3AVDibkOxKqgWQ6cEATOkk9nSQo63sxN1SdDm9NaYiywElBuECg0q_3HZRMtlDV9TKVFTHkMiTpXoIcBevzwj9DFS31p27We1qiOQElnplzaEGOB1RCopPrjuSqUjwOeZvQqg_eCKfE5uZnHB5UcodY6kzLPGfMYxHmwDM1y2g3zqZXq_0fcgYlQ5Dam8TvJj0FESxo46xZqE5lqd1jy1GPpKm8xEW4blh4RqhEqyecu8lZQzYb3sGUoLeK5xTVRwz3YKyf_O647gIfei0m1w2iCP3AdzJ5wMuDUwb1JlV65nxqnI05hycNg-rwTvtIgFonphjUUEPWFIlmNkAhZHE1RfZS6guZvAyrvuN3fHl9pPDnusbejKjMZZ5Mq1O2g_FVkuf2y2lep1sNRRbDGfAOFSZ97u800Okgp2dfDT9YzhMwEtH1sjns7aZ41Zxb3HteqrAJDb5V19SQUPniVxAVd02lZOVa68Ry83iAflAwXlzMCBis1DLxjYDNloUiMhUxMMTQcl9UWUiCr-n8O34mTZ8m6CioMRqpdw0GKqBhFj_jhCEc5x9wjSfBy8u0PTZOGpnHWi_apkXUEzGXoWbGDqNY2gcC8DSHpzTmdmjeBe5mXiSYms1opGjMvHpkSFzEsp3gkOzenZgzQy-p0wjwllF2JwqgEF0x-NdolhfissuS8h3Xo1iuVb3dUysFmI4vwfclRcklLUHUH8JqZdoCLwTrW7YOwlbArrlVbDYI2lgmWDl27f0rD1QaLRTbCZX0Vlc31wkIpdsxuiJbE78yCcNgX1VIHyq8TuyVCYNJ0c-0unp8QSnqerSy0QBhuE1wG9mUN-gqlvl_eNSn-wkQHZoCBjbgvNfWNmexr6B6cXgsG-iQW3Fa6-HYFRkanAX42YaxqzoHMj2Dva63x51CjUy8-dZBkqMHO51evIpRKxkpqXypBberU5RxFRKN59mesHDMrjh_nA5lIq7k9YoHPgJNR8J7mxoSkycAJZeaiXOt1rn0jAPEIK2hNhDtzMMTgSnTrGte_-sPh-qp4rgf2xqdxf-81MMRYtAOrbecN7SD8xi5XjM7vXdUpn6P6eeCKTIuFKXNFVsCC_1zYqtsSgodmmG4qIEjj3jyOWwK2gmpctUdFBFa2SPp4-Pa-dazOI2f0G9OA4NRDCujN1rhjtSKToE7za9t1BqNPMABAVtkORrIuzitEFBeua8NZ5KcCAIdw7rdZ5ublvSbImnU5Zn-6SwpOSKQyuGji55NW90LiBH8kcqlVhJufh5NZxmfScBsxzqVTafcWrXa8GrQw33aAjFAjsXARmYMRUYFwCYrU3xExkKcnKKn2RwXrbETt8QPRiMqqcdB7jmfm1MtQZhA51iXOnImsKx7kzQf6gPxqLfYYcJlQ6JRjanlFCgcE4VOo46ceC6VhUu_c2YaohkYHR9GRkBCYzE-C6aWCDapfIejxd6to-5QONWArUnI3QCVUAwYF_cBA25sjXpO95pVRcl_nRcZROidlly8nWUMp3jdWBl9aPzt7-SrtBpuhRDftwAmu0Zl9z4pb9bloiKeLjklkuKlLZXG4OMlNPEIRkCIGlWuy2plG3zsTqIBRj4YDQNl3Uz6iiQv1flETs4AnMiPpSa4P1sFxELfd0ccl3nYDXguh0IHAQTaCJzKy8CCLgDMZsC_8KgAZ-JDJNm7NpRrgUOFGHFmIIrfFO6VBIFrily6jAYzB8pbVebHj-Qn3qLhyI8DHmi3PiaFQzhoGxPpl-DcJjEHbW3USzsuXUXNG02yfZN1lJvpuWwz9pPoofyj5mkQAHFhDIqYIIjzkMrwrsV4mCck3RipkUfbcO3CfUOUjN-cboy8Lbo7ZsJAg8kvo0NuBvEACnQhMGMvmSyEmzcn0AWdN1cxEtL15wv9lvebXl7A1DAmMWFl84Kwuha4TF23vfLLk58dEgUL-nMHCh1HuTRL07_604U5uW7A2QZNY3xfersMf3Jg6iCf7I_0FYf7fTofuilfCncuA-_YGF5qaane4VvsNofFfdADeguZ2RXbgP7cp23u0khcAGFGBj9_EfwVMqOD2yV064mc3H-T06ul4TNFrS2wgCXfw6NgcdnjxSYDW9Q4zcOzfMPolQE9BhGB4qoLLAs76B6KXzZs-9-Pyk_oN-E32ySdsTM72LV_u60_7t8XLGKkbNcuyVlEytCKh6EC7gvNVWLBJQBtQjg8nQZjz5IZulrQ8SzdlbxlVxSrUxfvOQf7sSXPNW7l9jeAoADXv5lzyd6iqQYZDiBDC58Yl7HHFqv2aNBWpVQo-JEmpUjG7tA4uqBJKb1rwBMDu83LM1ETisEus5tFMkx5c7J4txuGE2nHTn_dk405_B4om0Q3533Ve8zqQpqT-Zue6Oko1LREuMREPn6KLRDkt-4IwUie3Ciy8BOzr6q4K4-2DSN1AKBnsBg3DkQT_wM-R7MJXxh7KBP5MwyomghMie8TF2NqHk9k4J3eyc1JEGZRpUaz2Wc_TNwaRWxwo3ulifWmAZVxV_i3_zQFiU9AAOHjiiRpKCkBkadsYHfaRIESQssoLJkzjxc1E_arGmeeOvYIvjZ_WdHD2aOafTW7rUfFGrQf8M_Zv9FYmTpd9ey4VWQ9jDaYF1NM4jUWbc7sVqhL-R1JQGad2w9nJf-o05ItWwUb6UJuQJC1uPpI055iRsALcz_qTs29riZTA08mRr_05T3Vlsk_9004OENGKHEnGjzrukYsLZlyI1mZtiRC9uXOpuxQ-C-bqSioFCkB7vsCXHg8cDo-B-nJH8HOKGkB6JqrGGRaffF3dazv7goLlw6ZYsBPVF2G445HFDE9xLhSu_eE-tVKI-mhZ7E-i41o4KwThLEpBfCmQC9hd7enN1Flino6Jno93tYBC9D-64qcj9FwbB79NZDxi6aKHmE53RW--BkT7UkYQxmS54ssLkLghc93WoJuDz48DQIsviEX3egd1Bl4MBc8d1B1wg-dm9S3QKRJxn_xHJswFvE9sD5izMKUwvAZB9LR-mnST1plTlsLlw_Rud8gbSWQtd8qqBTmBnAGb2sM5SrYX1RmUAzPgJogTdzax_3IquWcxGHpMERU0Tt_ifjBwAuqaUXQBmHxkDR6c2wnMN9U-7awYVQJaFTVYG1Eofx94RzANqha4_Z4HdOtids4QeVtkCmAwGCMc_QHamXMJI56f5EeeoeRsveEbUkooVHlgWCTHY0ZXz92p2pHf3Zs0qTha-5-NuunUmjRE1ZdmtzMfpw8KgYj3aaA3lsbUgeSltfWFr0c2NcQ10bh6gPdgH6nut5p-WSGM1yydOEb_9xjDu8dK_41zpMQukzquUWBLvuGxVR5VnjJkJPpe23yGie6C3uVBbF2dR5njqfXuIx5ytCV1qobj5x5PeuNuDqyc54CyuVdLA5y3-ztU0jyBx1WdH-zYiyNuRYU1-U1joEgu6IgBwf2f3ln7AwOUyBhLncCD9KW5DZGr34IVlhZpzr9v8ST2J7gJO11y9DSMrg5QAAAAAAAAAAAAAAAAAAAAAABw0QGCAm
2026/05/26 14:07:21 verified with Signer PublicKey
```

note that you can't extract the public key at this point so what i ended up doing is generating the public key by 'reading' the vault structure using the following command 
`vault read transit/keys/my-sign-key` and marshalling it into PEM format

```bash
$ vault read transit/export/public-key/my-sign-key
        Error reading transit/export/public-key/my-sign-key: Error making API request.

        Namespace: admin/
        URL: GET https://vault-cluster-public-vault-c305537c.8639af5b.z1.hashicorp.cloud:8200/v1/transit/export/public-key/my-sign-key
        Code: 500. Errors:

        * 1 error occurred:
            * unknown key type ml-dsa for export type public-key
```


### Misc

#### Private Key formats

As mentioned, this repo only supports the `bare-seed` format.  I'm using that format for future compatiblity

* [OpenSSL Position and Plans on Private Key Formats for the ML-KEM and ML-DSA Post-quantum (PQ) Algorithms](https://openssl-library.org/post/2025-01-21-blog-positionandplans/)
* [Let’s All Agree to Use Seeds as ML-KEM Keys](https://words.filippo.io/ml-kem-seeds/)


##### openssl formats

Note that when you generate a private 
for `ml-dsa-65` using openssl, it defaults to a `seed-priv` custom mode described in [ml_dsa_codecs.c](https://github.com/openssl/openssl/blob/master/providers/implementations/encode_decode/ml_dsa_codecs.c#L160C1-L160C72):

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

#### Parsing and Generating JWK

If you needed to generate a JWK, you can use the `example/jwk/main.go` as a reference.  What that does is generates the JSON representation of any given key.  Note the `pub` field is the raw DER encoded `SubjectPublicKeyInfo` bytes


```json
{
  "keys": [
    {
      "kty": "AKP",
      "kid": "keyid_1",
      "alg": "ML-DSA-44",
      "pub": "TuLJIaUVFnl4Xl/FvfsBmJTSdXLmPX+qD4icxvkBJSjXXZBgba0Gtrk3SIOaBHTQzJFmEl/TWNcXgiZDdXhh0EEANKTfGvm6n+oR5U9AZqYyULGkHdSAnXZ4ocprlmDSl4U1/UlhSvkq9T2o0p1zXO3lk1JxJeV/SGRaU6Hssqhni2onN3aHwiJTySu4sfSorjS9WMfZSv+ujT4fERbb1Z/D4NULBHmfKh7ujRVsyxa3H166VFn8GBIhB1mfpYsvvm1M+oe4rjUtL55Fa7DF66CSMEqmNTLMf6eTLwdPh9ZDwgCNPf/4AZADFGxgOGKVanoV1r1qDkTwmUO71p0JJr+d/nQiV2RcuXlW/2FC7ftlWIOzD7AQOMc2sjptmSPeDerGpJKkyyRNTpD9fqnpT46+Fz6XdjnJnO07ItgHYIJFUUprk/UJVXgvK0smVubBm347UWGSiK3y1nNP6TUOi8AJfTWUZy4muiF7uh+EVHp3GjeL1S5gJTL7DAk6HmJt7r3VXCycS3dEx+0ZMIwsODZHVsp7F/9v82JV7xj7VVhfXZrXNFG7z8SJLYomO1K1pe9JnHFwYJfyVDQ7ngXF5Lw/OH1klzLsxGPibDocKcctbq366DRdiXN7cG7GVRskrqQ9aH56f1yHY/RR65NVfe3z7C38rmwczdQmdeiJmMsvlJ0hltK4gthQ72/YBPBHsPXTmTlIUxCetD5myC2Wu/JqPuwpd4mjcHClpRbWha7XJbdzL09Fl7Y66XSYk9L/2OhB5mYYOZ3HB6clbaY7nsCGuV5qyQOodhv0fx1OaP/FXg52tycc9kgC5RFsF9m0d+SrSiyRfT4wnJDIrtVaC4AD/1arxgstXcRd6sj8A/K1J1lckPuXcoHvBDckGzTI9KZf9ldLABYM4ZNrc5EGSLjPGcwplhJpeMckuRPRO7RyQumQwh7cna2Id7/BKfG2MCQBnSXOB+HCrKXO8WOJEm2vNoSshxATBjAvVENPhjNS7Ah3VALDm6pdKtfPbhdwMFLH8hogJAnq7CQWZt9aeOZ/W5a4tTRQt/yQQkfnSNbyusgpwibeWB0Ul5S7HmxTh32VDuP7MvCVBXki3dOf+J30evuXMdPjOaelD1GZU0xcytVToLiRNk57GNNg42KrkFHKSXcTufwHdzpbT3l5aHcJtWsqRLiBy6pJYTpvF4jhzmIO/rmqPmdIwtod/+cj/DfNZfYmvzp+D29EfWVcMeOqmcBi7DFa0N0zMkZNEauG6UdZmdV+2CwhDmD4aGswxwYD6kHVAvn6dRq0P2rNd7DzOe4/FRymLQyHvcZQwVHvnzl1TZdvMLUo0yEv5YKntiRhcN+v+RRh7xBXbRYLl8oBP3BlBeQQHrLcng9vZDIYYAUpRWS2iif7kMa9ENsZ4jaDjCuYdqn4l/PKP2GjNMpluOHqp94ZpESSQdpQVUrQQcRosGIAseYxS7vd3mHP7ttRTN7RtbiOLVAIDiM2MXMoQnxMN9sHCGdS4xsjeRuV2Hsnd8eHvKmzL2CFJE2dA7OfkgT3psnzHYVYCZ2R4WwZFsXN3nJp/8ztIkLRanhVexs4H7PCXxn2sbJAA2nseFNAY4Ck04z9cFLfxNXJwR39DkV51yxzbq2P9sp8A7QS01wRFt35So+Vq9GJj7nq/mWZndTL1TvfM+4PHXfTuXuqA1GzhQ9e2AK4AcblfKY8dIkHshfREMIh/JDT7dLynyAkgTIP9D6ovaGzfjIyQQ=="
    },
    {
      "kty": "AKP",
      "kid": "keyid_2",
      "alg": "ML-DSA-65",
      "pub": "u42iVchx9qivlSkwM1m0SA9BbE47S/eMh7VX37ycqvyAD56H0B0Pse2QCqtsfts0yHVFtDIzES1jr81l6Gb6aw46rQZq4hWmYe/J71n2MTPJhfRAtYxx7VlLykwxqi5MT3TTAF+JQVY5mIkXks99z2BHHdRztMK3XUoiq8vbxi3d6GpJoaCHb6tZwXqDe1XqTCAVJvp+sROIHzGexcYsgtg77su97p3WdLpItJ1vzhHj2yIbc9UtTwLSid+TWE6nAf67k/kXxRssyFdVV8/5Nlz9JVAowqqT4xa37Qiv729FHCqkF3hO7fhSvU7ZoRA/2AR7ny7ryVfylehHD3TH72Y3qjhn2THwvXAy+bFu98yzCk+HIR3Vcht2uMij76Y/21uZPSYGNiePUKao/iWNA1uu+2QXo1v8JuDobn4hNmN9I+Y29trs2753uVFxKFTv9LztE5q8Qcxd65xkbvsW0DvWULsPuotaTb9m+HqzyK5LMaACcj/pFmJbi912Wb6MNOCsNO0V49QVbK3zjtyRNQF977v+k1u2OKX3x85MxO5yEZlJsXFvCjUmyQlaA42dRWxYf/u7XwDDc/K+y0ZB2+9EzfUdTUwZhvLTnR6P8vSmFuysVgI9lSHtSqJV/wUOeRyY1t44rfempxka2ZJQkZ7phZMZteHvvWed7tKYzuyBdGFIOXiao/bsqC/R7NouGnorKi1HGoyCW9jFgGyAq0vcz26nG1y8maKQFzSskFZT3D8ctyhtptMvOEC0MoWU+TGt0oTTfN+gs5jawIOil/bfSDRjo9YB/98C6S7GuGg38UFR9NEmAD7AXkSK1Hmj5CqwoecrIlAlVBx3zPvTssGk2Qx6dpe4FNEWOubN2LGM7Tr1d9ZZR/jVAFMIFu2DPfzFyHgQEr5+Qg5txi/ARMwFGiRzToOhZ/o+XraQsrkr8Z6JQ3qA0HgPhPtjPDTZ6WMDd/V5WZggKIrZmdqA9/YO6qhy25p2L8+mSS9pzBcQjusTpbrPelSgI5HCJuhQs+KmBGXmSV/DuliG9+CmzgPNwGNUKsEPOtNc1Xg+AFS53vVLAGRuYVHgsCmKhWCc+wJUIB1XsH2WrBIEWNQRC191/CkxXnNwbyg3tBigGYaN5hFf67tMPCsFJlYK72hFhAXVVoKFMgikZlDQPv0L/2PRS9R4NpThDVcZU9/6zptRD8COXEFHpaIdco9K7dHl13USnikdb/Btb582StSv6dPk0ZsT/rY1VhQUssTA3/OOeGDyh5feYsBP9/RLuQkdUVpislArhbifn0AIpQGK75xGnOjSgr4PDVIzCBo0HqTVB4K49syG6m0Ewo+dbAs9rpBjjWWSYwin2APOhKD9kEN/ysztv1EnFhobeQir2Ux62cDio7gP5/8LNkQ7GgblcxGffnXood/Gfxpv3MAN+iqiLdoH6ief9JSSiBwb0UmlHUvgKSzjVAK+Lo4Ef8xPwrUFBshPgsdD8nm0HXElOF003AMoyEZhYT28H5Y/fDyUtRM/d++aN+RigGPpk+jbhk4Sidbi241an3FGrFzcfyzsA9ofk6zYhXzIzNY3EunAS8yvOozXpnHsJ2+ceArGzUKLA+G96rknGghCgI+Uv7uMKNsfhHKHoPk7H+xnFefYCBUfZaVGVenXoWEBBJ/NHhof3eLRHHnbx3tAjX8ybhN+tvZiHstEDD6c+r1ulLJ2OUXKEIt3/03LK38Flb1p8h+T9vrmsUH7tIZ/8CQ+PCXOSzPw8W7WLvRea+W2Ime3Rq36Jd3cWAd4FLuL8ulTQLBe8hI5+OWycM6dVPoCTvkm4vmhhDGgIZl5sK9L1/HWoLdunz7j0Nbafa6Ip0DoxEJT00muL1oThjfvYGPVC33HvcHlLOySqIIIWp8EMW7dpnnQFKWYd2qpm8jSqO3FMbipFvQxwKlOYHRfNdVWO7+XC22Z3VnmFTgkdcmoLoSgp7/842mENhY388zPV90SionboRoKAZw2ROa55yMSwbTwhUrecyFkknwIC37vpEtOdcNFP8eMA5/Ztz7dV52shcD9sSIbZEimlK+acf/1i/Yj5feLaZgs3HVkyTuWDvERVSoFEXZ7lafFsYetocAyWde7qJYridU8dFyG80BMJV9qjYlbXJ4WGLo6bY2ujmDvIIfTZttz4dEw2gqIxQXVGwLJY7YOqvpDBWMuX1in1ucRNfxaFwv6oaMKQhHtgAf5W5CtOihz/sx46sg4lALpPiZVRuqEvXPbEsl8fxCEKXpiGCgbn/6GQvceZ9THQ6nggLcJTkMraqwibWXYPhdbJ4Hw9UoCn8W03rFNav4Z5jsNd25ehl5xTBl2hODi2uj6jdnO5JC7dxjdbgAGIXmYxaukSJO1ycJ6sVT1VxvIvEuSm5M9/5IXbnO1uWquMcyNLplf6KJybRq7A61vGHxqrliOdxA8k8AHcp31L4ZVDGGvNW+N0tFYBb+CJ+9dMyC2AYlDGrrshQXCG01VjXssgdWWaNhAjDgSTSZohi++IiO8A3YeGirSgvUFLMbjsD7Pzv/Ts/wdl+C13HDW5xEdNpdrl55GMfvuoq+4M2zoADsTF1HGGeEqacY3Go2jk7Q="
    },
    {
      "kty": "AKP",
      "kid": "keyid_3",
      "alg": "ML-DSA-87",
      "pub": "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"
    },
    {
      "kty": "AKP",
      "kid": "keyid_4",
      "alg": "ML-DSA-65",
      "pub": "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"
    }    
  ]
}

```
