package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
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
	"sync"
	"syscall"
	"time"

	"github.com/dchest/captcha"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
)

type Config struct {
	CertPath      string `json:"certPath, omitempty"`
	KeyPath       string `json:"keyPath, omitempty"`
	RedisAddr     string `json:"redisAddr, omitempty"`
	RedisPort     string `json:"redisPort, omitempty"`
	RedisPassword string `json:"redisPassword, omitempty"`
	RedisDB       int    `json:"redisDB, omitempty"`
	ListenAddr    string `json:"listenAddr"`
	ListenPort    string `json:"listenPort"`
	Secret        string `json:"secret_phrase"`
}

var (
	configPath = flag.String("conf", "", "Config File Path")
	ctx        = context.Background()
)

const (
	UNKNOWN_INNER_ERROR        = 1
	ITEM_DOES_NOT_EXIST        = 2
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
	cache  *redis.Client
	secret string
}

var bufPool = sync.Pool{
	New: func() interface{} {
		// The Pool's New function should generally only return pointer
		// types, since a pointer can be put into the return interface
		// value without an allocation:
		return new(bytes.Buffer)
	},
}

func (c *Captcha) CheckCaptchaIDExist(id string) bool {
	val, err := c.cache.Exists(ctx, id).Result()

	if err != nil || val != 1 {
		return false
	}

	val, err = c.cache.Exists(ctx, id+".scope").Result()

	if err != nil || val != 1 {
		return false
	}

	return true
}

func (c *Captcha) GenCaptcha(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

	//About scope, see https://github.com/InteractivePlus/InteractiveSSO-Captcha/issues/1
	scope := r.URL.Query().Get("scope")
	//Optical
	imgWidth := r.URL.Query().Get("width")
	imgHeight := r.URL.Query().Get("height")

	//Check whether scope is valid or not
	if scope == "" {
		ThrowError(w, REQUEST_PARAM_FORMAT_ERROR, "No Enough Params", "phrase")
		return
	}
	id := uuid.NewString()
	d := captcha.RandomDigits(5)

	_image := &captcha.Image{}
	_cdata := CaptchaData{}

	c.cache.Set(ctx, id, hex.EncodeToString(d), 10*time.Minute)
	c.cache.Set(ctx, id+".scope", scope, 10*time.Minute)

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
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	if err := jpeg.Encode(buf, _image.Paletted, nil); err != nil {
		ThrowError(w, UNKNOWN_INNER_ERROR, err.Error())
		return
	}

	_cdata.PhraseLen = 5
	_cdata.JpegBase64 = base64.StdEncoding.EncodeToString(buf.Bytes())
	ret := CaptchaRes{
		CaptchaId:   id,
		CaptchaDATA: _cdata,
		ExpireTime:  time.Now().UTC().Add(10 * time.Minute).Unix(),
	}

	WriteResult(w, http.StatusCreated, ret)
}

func (c *Captcha) Communicate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	_captchaID := ps.ByName("captcha_id")
	_secretPhrase := r.URL.Query().Get("secret_phrase")

	if _captchaID == "" || _secretPhrase == "" {
		ThrowError(w, REQUEST_PARAM_FORMAT_ERROR, "No Enough Params", "phrase")
		return
	}

	// Secure compare!!! DON'T MODIFY THIS
	if subtle.ConstantTimeCompare([]byte(c.secret), []byte(_secretPhrase)) == 1 {
		EXISTS := c.CheckCaptchaIDExist(_captchaID)
		if !EXISTS {
			ThrowError(w, ITEM_DOES_NOT_EXIST, "Items Not Exists", "captcha_id")
			return
		}
		scope, err := c.cache.Get(ctx, _captchaID+".scope").Result()
		if err != nil {
			ThrowError(w, UNKNOWN_INNER_ERROR, err.Error())
			return
		}
		var params = map[string]string{}
		params["scope"] = scope
		WriteResult(w, http.StatusOK, params)
	} else {
		ThrowError(w, CREDENTIAL_NOT_MATCH, "Secret Phrase Not correct", "secret_phrase")
	}

}

func (c *Captcha) HandleCaptcha(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	_captchaID := ps.ByName("captcha_id")

	_phrase := r.URL.Query().Get("phrase")

	if _phrase == "" || _captchaID == "" {
		ThrowError(w, REQUEST_PARAM_FORMAT_ERROR, "No Enough Params", "phrase")
		return
	}
	EXISTS := c.CheckCaptchaIDExist(_captchaID)

	if !EXISTS {
		ThrowError(w, ITEM_DOES_NOT_EXIST, "Items Not Exists", "captcha_id")
		return
	}

	hexVal, err := c.cache.Get(ctx, _captchaID).Result()

	if err != nil || hexVal == "" {
		ThrowError(w, ITEM_DOES_NOT_EXIST, "Items Not Exists", "captcha_id")
		return
	}

	val, _ := hex.DecodeString(hexVal)

	if !bytes.Equal(val, ConvertStringToByte(_phrase)) {
		ThrowError(w, CREDENTIAL_NOT_MATCH, "Phrase Not correct", "phrase")
		return
	}

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

	if conf.Secret == "" {
		log.Fatal("No Secret Phrase")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	rdo := &redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	}

	if conf.RedisDB != 0 {
		rdo.DB = conf.RedisDB
	}

	if conf.RedisAddr != "" && conf.RedisPort != "" {
		rdo.Addr = fmt.Sprintf("%s:%s", conf.RedisAddr, conf.RedisPort)
	}

	if conf.RedisPassword != "" {
		rdo.Password = conf.RedisPassword
	}
	rdb := redis.NewClient(rdo)
	defer rdb.Close()
	//Try to connect to the redis server
	if err = rdb.Ping(ctx).Err(); err != nil {
		log.Fatal("Fail to connect to redis")
	}

	sig := make(chan struct{})
	router := httprouter.New()
	C := &Captcha{
		cache:  rdb,
		secret: conf.Secret,
	}
	router.GET("/captcha", C.GenCaptcha)
	router.GET("/captcha/:captcha_id/submitStatus", C.Communicate)
	router.GET("/captcha/:captcha_id/submitResult", C.HandleCaptcha)

	srv := &http.Server{
		Handler: router,
		Addr:    fmt.Sprintf("%s:%s", conf.ListenAddr, conf.ListenPort),
	}

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

	for {
		select {
		case <-sigCh:
			if err := srv.Shutdown(context.Background()); err != nil {
				log.Printf("HTTP server Shutdown: %v", err)
			}
		case <-sig:
			log.Println("HTTP Server Exits")
			return
		}
	}

}
