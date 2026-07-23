// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

// Cryptography operations (recipe tranche 2 toward CyberChef parity): symmetric
// block/stream ciphers and the classic ciphers. Standard-library crypto only, so
// the module stays dependency-free and TinyGo-clean. Ops are byte->byte and emit
// raw ciphertext; chain To Hex / To Base64 for a printable form (more composable
// than a built-in output encoding). RSA/asymmetric is a separate tranche.
package ops

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

func init() {
	registerBlockCiphers()
	registerStreamCiphers()
	registerClassicCiphers()
}

// ---- key material ----------------------------------------------------------

// parseKeyMaterial decodes a key or IV string per the chosen format. Unknown or
// empty format falls back to hex (the dominant convention for crypto keys); the
// UI always sends an explicit format, so the fallback is for programmatic use.
func parseKeyMaterial(s, format string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "utf8", "utf-8", "latin1", "raw":
		return []byte(s), nil
	case "base64":
		return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	default: // hex
		return parseHexLoose(s)
	}
}

var keyFormatParam = Param{Name: "keyFormat", Label: "Key format", Type: ParamSelect, Default: "Hex", Options: []string{"Hex", "UTF8", "Base64"}}
var ivFormatParam = Param{Name: "ivFormat", Label: "IV format", Type: ParamSelect, Default: "Hex", Options: []string{"Hex", "UTF8", "Base64"}}

// blockParams builds the standard mode/key/iv parameter set for a block cipher,
// with modes[0] the default mode.
func blockParams(modes []string) []Param {
	return []Param{
		{Name: "mode", Label: "Mode", Type: ParamSelect, Default: modes[0], Options: modes},
		{Name: "key", Label: "Key", Type: ParamText},
		keyFormatParam,
		{Name: "iv", Label: "IV / Nonce", Type: ParamText},
		ivFormatParam,
	}
}

// ---- PKCS#7 padding --------------------------------------------------------

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("decrypt: data is not a whole number of blocks")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize {
		return nil, errors.New("decrypt: invalid PKCS#7 padding (wrong key/IV?)")
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, errors.New("decrypt: invalid PKCS#7 padding (wrong key/IV?)")
		}
	}
	return data[:len(data)-pad], nil
}

// ---- block cipher core -----------------------------------------------------

func blockEncrypt(block cipher.Block, mode string, iv, data []byte) ([]byte, error) {
	bs := block.BlockSize()
	switch mode {
	case "CBC":
		if len(iv) != bs {
			return nil, fmt.Errorf("CBC needs a %d-byte IV, got %d", bs, len(iv))
		}
		padded := pkcs7Pad(data, bs)
		out := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
		return out, nil
	case "ECB":
		padded := pkcs7Pad(data, bs)
		out := make([]byte, len(padded))
		for i := 0; i < len(padded); i += bs {
			block.Encrypt(out[i:i+bs], padded[i:i+bs])
		}
		return out, nil
	case "CTR", "CFB", "OFB":
		if len(iv) != bs {
			return nil, fmt.Errorf("%s needs a %d-byte IV, got %d", mode, bs, len(iv))
		}
		out := make([]byte, len(data))
		streamFor(block, mode, iv, true).XORKeyStream(out, data)
		return out, nil
	case "GCM":
		if len(iv) == 0 {
			return nil, errors.New("GCM needs a nonce (IV)")
		}
		aead, err := cipher.NewGCMWithNonceSize(block, len(iv))
		if err != nil {
			return nil, err
		}
		return aead.Seal(nil, iv, data, nil), nil // appends the 16-byte auth tag
	}
	return nil, fmt.Errorf("unknown mode %q", mode)
}

func blockDecrypt(block cipher.Block, mode string, iv, data []byte) ([]byte, error) {
	bs := block.BlockSize()
	switch mode {
	case "CBC":
		if len(iv) != bs {
			return nil, fmt.Errorf("CBC needs a %d-byte IV, got %d", bs, len(iv))
		}
		if len(data)%bs != 0 {
			return nil, errors.New("decrypt: ciphertext is not a whole number of blocks")
		}
		out := make([]byte, len(data))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
		return pkcs7Unpad(out, bs)
	case "ECB":
		if len(data)%bs != 0 {
			return nil, errors.New("decrypt: ciphertext is not a whole number of blocks")
		}
		out := make([]byte, len(data))
		for i := 0; i < len(data); i += bs {
			block.Decrypt(out[i:i+bs], data[i:i+bs])
		}
		return pkcs7Unpad(out, bs)
	case "CTR", "CFB", "OFB":
		if len(iv) != bs {
			return nil, fmt.Errorf("%s needs a %d-byte IV, got %d", mode, bs, len(iv))
		}
		out := make([]byte, len(data))
		streamFor(block, mode, iv, false).XORKeyStream(out, data)
		return out, nil
	case "GCM":
		if len(iv) == 0 {
			return nil, errors.New("GCM needs a nonce (IV)")
		}
		aead, err := cipher.NewGCMWithNonceSize(block, len(iv))
		if err != nil {
			return nil, err
		}
		return aead.Open(nil, iv, data, nil) // verifies the tag; errors if tampered
	}
	return nil, fmt.Errorf("unknown mode %q", mode)
}

// streamFor builds the keystream generator for the stream modes. CFB is
// direction-specific; CTR and OFB are symmetric.
func streamFor(block cipher.Block, mode string, iv []byte, encrypt bool) cipher.Stream {
	switch mode {
	case "CTR":
		return cipher.NewCTR(block, iv)
	case "OFB":
		return cipher.NewOFB(block, iv)
	default: // CFB
		if encrypt {
			return cipher.NewCFBEncrypter(block, iv)
		}
		return cipher.NewCFBDecrypter(block, iv)
	}
}

// symmetricRun wires an Op to a block-cipher constructor and a direction.
func symmetricRun(newBlock func([]byte) (cipher.Block, error), encrypt bool) func([]byte, Args) ([]byte, error) {
	return func(in []byte, a Args) ([]byte, error) {
		key, err := parseKeyMaterial(a.Get("key"), a.Get("keyFormat"))
		if err != nil {
			return nil, fmt.Errorf("key: %w", err)
		}
		block, err := newBlock(key)
		if err != nil {
			return nil, err
		}
		mode := strings.ToUpper(strings.TrimSpace(a.Get("mode")))
		if mode == "" {
			mode = "CBC"
		}
		var iv []byte
		if mode != "ECB" {
			if iv, err = parseKeyMaterial(a.Get("iv"), a.Get("ivFormat")); err != nil {
				return nil, fmt.Errorf("iv: %w", err)
			}
		}
		if encrypt {
			return blockEncrypt(block, mode, iv, in)
		}
		return blockDecrypt(block, mode, iv, in)
	}
}

func registerBlockCiphers() {
	aesModes := []string{"CBC", "CFB", "OFB", "CTR", "GCM", "ECB"}
	desModes := []string{"CBC", "CFB", "OFB", "CTR", "ECB"} // GCM needs a 128-bit block
	reg(Op{ID: "aes-encrypt", Name: "AES Encrypt", Category: "Cipher", Params: blockParams(aesModes), run: symmetricRun(aes.NewCipher, true)})
	reg(Op{ID: "aes-decrypt", Name: "AES Decrypt", Category: "Cipher", Params: blockParams(aesModes), run: symmetricRun(aes.NewCipher, false)})
	reg(Op{ID: "des-encrypt", Name: "DES Encrypt", Category: "Cipher", Params: blockParams(desModes), run: symmetricRun(des.NewCipher, true)})
	reg(Op{ID: "des-decrypt", Name: "DES Decrypt", Category: "Cipher", Params: blockParams(desModes), run: symmetricRun(des.NewCipher, false)})
	reg(Op{ID: "triple-des-encrypt", Name: "Triple DES Encrypt", Category: "Cipher", Params: blockParams(desModes), run: symmetricRun(des.NewTripleDESCipher, true)})
	reg(Op{ID: "triple-des-decrypt", Name: "Triple DES Decrypt", Category: "Cipher", Params: blockParams(desModes), run: symmetricRun(des.NewTripleDESCipher, false)})
}

// ---- stream ciphers --------------------------------------------------------

func registerStreamCiphers() {
	reg(Op{ID: "rc4", Name: "RC4", Category: "Cipher", Params: []Param{
		{Name: "key", Label: "Key", Type: ParamText},
		{Name: "keyFormat", Label: "Key format", Type: ParamSelect, Default: "UTF8", Options: []string{"Hex", "UTF8", "Base64"}},
	}, run: func(in []byte, a Args) ([]byte, error) {
		key, err := parseKeyMaterial(a.Get("key"), a.Get("keyFormat"))
		if err != nil {
			return nil, fmt.Errorf("key: %w", err)
		}
		c, err := rc4.NewCipher(key)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(in))
		c.XORKeyStream(out, in)
		return out, nil
	}})
}

// ---- classic ciphers -------------------------------------------------------

func registerClassicCiphers() {
	reg(Op{ID: "rot13", Name: "ROT13", Category: "Cipher", Params: []Param{
		{Name: "amount", Label: "Amount", Type: ParamNumber, Default: "13"},
	}, run: func(in []byte, a Args) ([]byte, error) {
		return rotAlpha(in, a.Int("amount", 13)), nil
	}})
	reg(Op{ID: "rot47", Name: "ROT47", Category: "Cipher", Params: []Param{
		{Name: "amount", Label: "Amount", Type: ParamNumber, Default: "47"},
	}, run: func(in []byte, a Args) ([]byte, error) {
		return rot47(in, a.Int("amount", 47)), nil
	}})
	reg(Op{ID: "atbash", Name: "Atbash", Category: "Cipher", run: func(in []byte, a Args) ([]byte, error) {
		out := make([]byte, len(in))
		for i, b := range in {
			switch {
			case b >= 'a' && b <= 'z':
				out[i] = 'z' - (b - 'a')
			case b >= 'A' && b <= 'Z':
				out[i] = 'Z' - (b - 'A')
			default:
				out[i] = b
			}
		}
		return out, nil
	}})
	affineParams := []Param{
		{Name: "a", Label: "a (coprime with 26)", Type: ParamNumber, Default: "5"},
		{Name: "b", Label: "b", Type: ParamNumber, Default: "8"},
	}
	reg(Op{ID: "affine-encode", Name: "Affine Encode", Category: "Cipher", Params: affineParams, run: func(in []byte, a Args) ([]byte, error) {
		return affine(in, a.Int("a", 5), a.Int("b", 8), false)
	}})
	reg(Op{ID: "affine-decode", Name: "Affine Decode", Category: "Cipher", Params: affineParams, run: func(in []byte, a Args) ([]byte, error) {
		return affine(in, a.Int("a", 5), a.Int("b", 8), true)
	}})
	keyParam := []Param{{Name: "key", Label: "Key", Type: ParamText}}
	reg(Op{ID: "vigenere-encode", Name: "Vigenère Encode", Category: "Cipher", Params: keyParam, run: func(in []byte, a Args) ([]byte, error) {
		return vigenere(in, a.Get("key"), false)
	}})
	reg(Op{ID: "vigenere-decode", Name: "Vigenère Decode", Category: "Cipher", Params: keyParam, run: func(in []byte, a Args) ([]byte, error) {
		return vigenere(in, a.Get("key"), true)
	}})
}

// rotAlpha shifts ASCII letters by n (Caesar), wrapping within each case and
// leaving everything else untouched. Negative and >26 values normalize.
func rotAlpha(in []byte, n int) []byte {
	s := byte(((n % 26) + 26) % 26)
	out := make([]byte, len(in))
	for i, b := range in {
		switch {
		case b >= 'a' && b <= 'z':
			out[i] = 'a' + (b-'a'+s)%26
		case b >= 'A' && b <= 'Z':
			out[i] = 'A' + (b-'A'+s)%26
		default:
			out[i] = b
		}
	}
	return out
}

// rot47 shifts visible ASCII (0x21..0x7e, 94 chars) by n.
func rot47(in []byte, n int) []byte {
	s := ((n % 94) + 94) % 94
	out := make([]byte, len(in))
	for i, b := range in {
		if b >= '!' && b <= '~' {
			out[i] = '!' + byte((int(b-'!')+s)%94)
		} else {
			out[i] = b
		}
	}
	return out
}

func affine(in []byte, a, b int, decode bool) ([]byte, error) {
	a = ((a % 26) + 26) % 26
	inv, ok := modInverse(a, 26)
	if !ok {
		return nil, fmt.Errorf("affine: a=%d is not coprime with 26", a)
	}
	out := make([]byte, len(in))
	shift := func(base, ch byte) byte {
		x := int(ch - base)
		var y int
		if decode {
			y = (inv * (((x-b)%26 + 26) % 26)) % 26
		} else {
			y = (a*x + b) % 26
		}
		return base + byte(((y%26)+26)%26)
	}
	for i, ch := range in {
		switch {
		case ch >= 'a' && ch <= 'z':
			out[i] = shift('a', ch)
		case ch >= 'A' && ch <= 'Z':
			out[i] = shift('A', ch)
		default:
			out[i] = ch
		}
	}
	return out, nil
}

func modInverse(a, m int) (int, bool) {
	a = ((a % m) + m) % m
	for x := 1; x < m; x++ {
		if (a*x)%m == 1 {
			return x, true
		}
	}
	return 0, false
}

// vigenere shifts each letter by the corresponding key letter (key letters only;
// the key index advances only on plaintext letters, the classic convention).
func vigenere(in []byte, key string, decode bool) ([]byte, error) {
	var k []int
	for _, r := range strings.ToLower(key) {
		if r >= 'a' && r <= 'z' {
			k = append(k, int(r-'a'))
		}
	}
	if len(k) == 0 {
		return nil, errors.New("vigenère: key must contain letters")
	}
	out := make([]byte, len(in))
	ki := 0
	for i, b := range in {
		shift := k[ki%len(k)]
		if decode {
			shift = -shift
		}
		switch {
		case b >= 'a' && b <= 'z':
			out[i] = 'a' + byte(((int(b-'a')+shift)%26+26)%26)
			ki++
		case b >= 'A' && b <= 'Z':
			out[i] = 'A' + byte(((int(b-'A')+shift)%26+26)%26)
			ki++
		default:
			out[i] = b
		}
	}
	return out, nil
}
