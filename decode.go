package microprogram

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

type decoder struct {
	appId string
}

func NewDecoder(appId string) *decoder {
	return &decoder{
		appId: appId,
	}
}

func (d *decoder) Decode(key, iv, encryptedData string) ([]byte, error) {
	dkey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	div, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return nil, err
	}

	ddata, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	//解密
	block, err := aes.NewCipher(dkey)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, div)
	mode.CryptBlocks(ddata, ddata)
	return ddata, nil
}
