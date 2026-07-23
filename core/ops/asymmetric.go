// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

// RSA / asymmetric operations (recipe tranche 9 toward CyberChef parity).
// Standard library, but this pulls in crypto/rand, whose wasm randomness import
// TinyGo does not wire: the tool bundle's boot script provides that import from
// the platform CSPRNG (see recipe/ui/index.tmpl.html). Keys are PEM (PKCS#1 or
// PKCS#8/PKIX). Byte->byte; signatures/ciphertext are raw (chain To Hex).
package ops

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"strings"
)

func init() {
	registerRSA()
}

func registerRSA() {
	keyParam := Param{Name: "key", Label: "PEM key", Type: ParamText}
	padParam := Param{Name: "padding", Label: "Padding", Type: ParamSelect, Default: "OAEP", Options: []string{"OAEP", "PKCS1v15"}}
	hashParam := Param{Name: "hash", Label: "Hash", Type: ParamSelect, Default: "SHA256", Options: []string{"SHA1", "SHA256", "SHA512"}}
	schemeParam := Param{Name: "scheme", Label: "Scheme", Type: ParamSelect, Default: "PKCS1v15", Options: []string{"PKCS1v15", "PSS"}}

	reg(Op{ID: "rsa-encrypt", Name: "RSA Encrypt", Category: "Cipher", Params: []Param{keyParam, padParam, hashParam}, run: func(in []byte, a Args) ([]byte, error) {
		pub, err := parseRSAPublic(a.Get("key"))
		if err != nil {
			return nil, err
		}
		_, hnew := rsaHash(a.Get("hash"))
		if strings.EqualFold(a.Get("padding"), "PKCS1v15") {
			return rsa.EncryptPKCS1v15(rand.Reader, pub, in)
		}
		return rsa.EncryptOAEP(hnew(), rand.Reader, pub, in, nil)
	}})
	reg(Op{ID: "rsa-decrypt", Name: "RSA Decrypt", Category: "Cipher", Params: []Param{keyParam, padParam, hashParam}, run: func(in []byte, a Args) ([]byte, error) {
		priv, err := parseRSAPrivate(a.Get("key"))
		if err != nil {
			return nil, err
		}
		_, hnew := rsaHash(a.Get("hash"))
		if strings.EqualFold(a.Get("padding"), "PKCS1v15") {
			return rsa.DecryptPKCS1v15(rand.Reader, priv, in)
		}
		return rsa.DecryptOAEP(hnew(), rand.Reader, priv, in, nil)
	}})
	reg(Op{ID: "rsa-sign", Name: "RSA Sign", Category: "Cipher", Params: []Param{keyParam, schemeParam, hashParam}, run: func(in []byte, a Args) ([]byte, error) {
		priv, err := parseRSAPrivate(a.Get("key"))
		if err != nil {
			return nil, err
		}
		ch, hnew := rsaHash(a.Get("hash"))
		d := hnew()
		d.Write(in)
		digest := d.Sum(nil)
		if strings.EqualFold(a.Get("scheme"), "PSS") {
			return rsa.SignPSS(rand.Reader, priv, ch, digest, nil)
		}
		return rsa.SignPKCS1v15(rand.Reader, priv, ch, digest)
	}})
	reg(Op{ID: "rsa-verify", Name: "RSA Verify", Category: "Cipher", Params: []Param{
		keyParam, schemeParam, hashParam,
		{Name: "signature", Label: "Signature", Type: ParamText},
		{Name: "sigFormat", Label: "Signature format", Type: ParamSelect, Default: "Hex", Options: []string{"Hex", "Base64"}},
	}, run: func(in []byte, a Args) ([]byte, error) {
		pub, err := parseRSAPublic(a.Get("key"))
		if err != nil {
			return nil, err
		}
		sig, err := parseSignature(a.Get("signature"), a.Get("sigFormat"))
		if err != nil {
			return nil, fmt.Errorf("signature: %w", err)
		}
		ch, hnew := rsaHash(a.Get("hash"))
		d := hnew()
		d.Write(in)
		digest := d.Sum(nil)
		if strings.EqualFold(a.Get("scheme"), "PSS") {
			err = rsa.VerifyPSS(pub, ch, digest, sig, nil)
		} else {
			err = rsa.VerifyPKCS1v15(pub, ch, digest, sig)
		}
		if err != nil {
			return nil, fmt.Errorf("signature does not verify: %w", err)
		}
		return []byte("Signature valid."), nil
	}})
}

func rsaHash(name string) (crypto.Hash, func() hash.Hash) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "SHA1":
		return crypto.SHA1, sha1.New
	case "SHA512":
		return crypto.SHA512, sha512.New
	default:
		return crypto.SHA256, sha256.New
	}
}

func parseSignature(s, format string) ([]byte, error) {
	if strings.EqualFold(format, "Base64") {
		return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	}
	return parseHexLoose(s)
}

func parseRSAPublic(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemStr)))
	if block == nil {
		return nil, errors.New("no PEM block found in key")
	}
	if k, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PublicKey); ok {
			return rk, nil
		}
		return nil, errors.New("PEM key is not an RSA public key")
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		if rk, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return rk, nil
		}
	}
	return nil, errors.New("could not parse an RSA public key (expected PKCS#1, PKIX, or a certificate)")
}

func parseRSAPrivate(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemStr)))
	if block == nil {
		return nil, errors.New("no PEM block found in key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, errors.New("PEM key is not an RSA private key")
	}
	return nil, errors.New("could not parse an RSA private key (expected PKCS#1 or PKCS#8)")
}
