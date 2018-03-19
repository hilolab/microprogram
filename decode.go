package microprogram

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
)

type decoder struct {
	appID string
}

type Data struct {
	OpenID    string `json:"openId"`
	NickName  string `json:"nickName"`
	Gender    uint8  `json:"gender"`
	Language  string `json:"language"`
	City      string `json:"city"`
	Province  string `json:"province"`
	Country   string `json:"country"`
	AvatarURL string `json:"avatarUrl"`
	UnionID   string `json:"unionId"`
	Watermark struct {
		Timestamp int64  `json:"timestamp"`
		AppID     string `json:"appid"`
	} `json:"watermark"`
}

func NewDecoder(appID string) *decoder {
	return &decoder{
		appID: appID,
	}
}

func (d *decoder) Decode(key, iv, encryptedData string) (*Data, error) {
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

	l := len(ddata)
	var i = 1
	for i <= l {
		if ddata[l-i] == 125 {
			ddata = ddata[:l-i+1]
			break
		}
		i++
	}

	data := &Data{}
	err = json.Unmarshal(ddata, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}
