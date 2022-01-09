package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"image/jpeg"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/InteractivePlus/InteractiveSSO-Captcha/cache"
	"github.com/dchest/captcha"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
)

type Config struct {
	CertPath   string `json:"certPath, omitempty"`
	KeyPath    string `json:"keyPath, omitempty"`
	ListenAddr string `json:"listenAddr"`
	ListenPort string `json:"listenPort"`
}

var (
	configPath = flag.String("conf", "", "Config File Path")
)

const (
	UNKNOWN_INNER_ERROR        = 1
	CREDENTIAL_NOT_MATCH       = 14
	REQUEST_PARAM_FORMAT_ERROR = 20
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

type Captcha struct {
	cache *cache.LruCache
}

func (c *Captcha) GenCaptcha(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	imgWidth := r.URL.Query().Get("width")
	imgHeight := r.URL.Query().Get("height")
	id := uuid.NewString()
	d := captcha.RandomDigits(5)
	var buf bytes.Buffer
	var _image captcha.Image
	_cdata := CaptchaData{}

	c.cache.Set(id, string(d))
	if imgHeight != "" && imgHeight != "" {
		width, _ := strconv.Atoi(imgWidth)
		height, _ := strconv.Atoi(imgHeight)
		_image = captcha.NewImage(id, d, width, height)
		_cdata.Width = width
		_cdata.Height = height
	} else {
		_image = captcha.NewImage(id, d, 150, 40)
		_cdata.Width = 150
		_cdata.Height = 40
	}

	if err := jpeg.Encode(&buf, _image.Paletted, nil); err != nil {
		ThrowError(w, UNKNOWN_INNER_ERROR, err.Error())
	}

	ret := CaptchaRes{}
	_cdata.PhraseLen = 5
	_cdata.JpegBase64 = base64.StdEncoding.EncodeToString(buf.Bytes())
	ret.CaptchaId = id
	ret.CaptchaDATA = _cdata
	ret.ExpireTime = time.Now().UTC().Unix() + 600

	WriteResult(w, http.StatusCreated, ret)
}

func (c *Captcha) HandleCaptcha(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	_captchaID := ps.ByName("captcha_id")

	_phrase := r.URL.Query().Get("phrase")

	if _phrase == "" {
		ThrowError(w, REQUEST_PARAM_FORMAT_ERROR, "No Enough Params", "phrase")
		return
	}

	d, EXISTS := c.cache.Get(_captchaID)

	if !EXISTS {
		ThrowError(w, CREDENTIAL_NOT_MATCH, "No Such id", "phrase")
		return
	}

	if d.(string) != _phrase {
		ThrowError(w, CREDENTIAL_NOT_MATCH, "Phrase Not correct", "phrase")
	}
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

func main() {
	flag.Parse()

	if _, err := os.Stat(*configPath); errors.Is(err, os.ErrNotExist) {
		log.Fatal("Config File does not exist")
	}

	data, err := os.ReadFile(*configPath)

	if err != nil {
		log.Fatal(err)
	}

	var conf Config
	if err = json.Unmarshal(data, &conf); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := make(chan struct{})
	router := httprouter.New()

	C := &Captcha{
		cache: cache.NewLRUCache(cache.WithAge(650)),
	}
	router.GET("/captcha", C.GenCaptcha)
	router.GET("/captcha/:captcha_id/submitResult", C.HandleCaptcha)

	srv := &http.Server{
		Handler: router,
		Addr:    fmt.Sprintf("%s:%s", conf.ListenAddr, conf.ListenPort),
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				if err := srv.Shutdown(context.Background()); err != nil {
					log.Printf("HTTP server Shutdown: %v", err)
				}
			case <-sig:
				log.Println("HTTP Server Exits")
				return
			}
		}
	}()

	go func() {
		defer close(sig)
		if conf.CertPath == "" || conf.KeyPath == "" {
			if err := srv.ListenAndServe(); err != http.ErrServerClosed {
				log.Printf("ListenAndServe(): %v", err)
				return
			}
		} else {
			if err := srv.ListenAndServeTLS(conf.CertPath, conf.KeyPath); err != http.ErrServerClosed {
				log.Printf("ListenAndServe(): %v", err)
				return
			}
		}
	}()

	<-sigCh

	cancel()

	log.Println("HTTP Exit")
}
