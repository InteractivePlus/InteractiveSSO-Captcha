package main

import (
	"encoding/json"
	"net/http"
	"time"
)

const (
	UNKNOWN_INNER_ERROR        = 1
	ITEM_DOES_NOT_EXIST        = 2
	CREDENTIAL_NOT_MATCH       = 14
	REQUEST_PARAM_FORMAT_ERROR = 20
	EXPIRE                     = 10 * time.Minute
)

type GeneralResult struct {
	ErrCode             int             `json:"errorCode"`
	ErrorDescription    string          `json:"errorDescription,omitempty"`
	ErrorFile           string          `json:"errorFile,omitempty"`
	ErrorLine           int             `json:"errorLine,omitempty"`
	ErrorParam          string          `json:"errorParam,omitempty"`
	Item                string          `json:"item,omitempty"`
	Credential          string          `json:"credential,omitempty"`
	UserDefinedRootData string          `json:"user-defined-root-data,omitempty"`
	Data                json.RawMessage `json:"data,omitempty"`
	SubmitSuccess       bool            `json:"submitSuccess,omitempty"`
}

type CaptchaData struct {
	Width      int    `json:"width"`
	Height     int    `json:"height"`
	JpegBase64 string `json:"jpegBase64"`
	PhraseLen  int    `json:"phraseLen"`
}

type CaptchaRes struct {
	CaptchaId   string      `json:"captcha_id"`
	ExpireTime  int64       `json:"expire_time"`
	CaptchaDATA CaptchaData `json:"captcha_data"`
}

func ConvertStringToByte(digits string) []byte {
	if digits == "" {
		return nil
	}
	ns := make([]byte, len(digits))
	for i := range ns {
		d := digits[i]
		switch {
		case '0' <= d && d <= '9':
			ns[i] = d - '0'
		case d == ' ' || d == ',':
			// ignore
		default:
			return nil
		}
	}
	return ns
}

func ThrowError(w http.ResponseWriter, ErrorType int, ErrorDescription string, opts ...string) {
	_newErr := &GeneralResult{
		ErrCode:          ErrorType,
		ErrorDescription: ErrorDescription,
	}
	switch ErrorType {
	case REQUEST_PARAM_FORMAT_ERROR:
		_newErr.ErrorParam = opts[0]
	case CREDENTIAL_NOT_MATCH:
		_newErr.Credential = opts[0]
	}

	ret, _ := json.Marshal(_newErr)
	w.Write(ret)
}

func WriteResult(w http.ResponseWriter, httpCode int, ret interface{}) {
	_newRet := &GeneralResult{
		ErrCode: 0,
	}

	_newRet.Data, _ = json.Marshal(ret)

	_ret, _ := json.Marshal(_newRet)

	w.WriteHeader(httpCode)
	w.Write(_ret)
}
