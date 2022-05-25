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
	ListenPort    string `json:"listenPort, omitempty"`
	Secret        string `json:"secret_phrase, omitempty"`
}

var (
	configPath = flag.String("conf", "", "Config File Path")
	ctx        = context.Background()
)

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
		ThrowError(w, REQUEST_PARAM_FORMAT_ERROR, "No Enough Params", "scope")
		return
	}
	id := uuid.NewString()
	d := captcha.RandomDigits(5)

	_image := &captcha.Image{}
	_cdata := CaptchaData{}

	c.cache.Set(ctx, id, hex.EncodeToString(d), EXPIRE)
	c.cache.Set(ctx, id+".scope", scope, EXPIRE)

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
		ExpireTime:  time.Now().UTC().Add(EXPIRE).Unix(),
	}

	WriteResult(w, http.StatusCreated, ret)
}

func (c *Captcha) SubmitStatus(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	_captchaID := ps.ByName("captcha_id")
	_secretPhrase := r.URL.Query().Get("secret_phrase")

	if _captchaID == "" {
		ThrowError(w, REQUEST_PARAM_FORMAT_ERROR, "No Enough Params", "captcha_id")
		return
	}
	if _secretPhrase == "" {
		ThrowError(w, REQUEST_PARAM_FORMAT_ERROR, "No Enough Params", "secret_phrase")
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
		//Record the status

		c.cache.Set(ctx, _captchaID+".status", "1", EXPIRE)
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

func (c *Captcha) CheckSubmitStatus(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	_captchaID := ps.ByName("captcha_id")
	if _captchaID == "" {
		ThrowError(w, REQUEST_PARAM_FORMAT_ERROR, "No Enough Params", "phrase")
		return
	}

	status, err := c.cache.Get(ctx, _captchaID+".status").Result()
	scope, _ := c.cache.Get(ctx, _captchaID+".scope").Result()
	var params = map[string]interface{}{}
	params["scope"] = scope
	if err != nil || status != "1" {
		params["submitSuccess"] = false
	} else {
		params["submitSuccess"] = true
	}

	WriteResult(w, http.StatusOK, params)
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

	if conf.Secret == "" && os.Getenv("SECRET_KEY") != "" {
		conf.Secret = os.Getenv("SECRET_KEY")
	}
	if conf.Secret == "" {
		log.Fatal("No Secret Phrase")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	rdo := &redis.Options{
		Addr:     "", //No Addr Set
		Password: "", // no password set
		DB:       0,  // use default DB
	}

	if conf.RedisDB != 0 {
		rdo.DB = conf.RedisDB
	}

	if conf.RedisAddr != "" && conf.RedisPort != "" {
		rdo.Addr = fmt.Sprintf("%s:%s", conf.RedisAddr, conf.RedisPort)
	} else if os.Getenv("REDIS_ADDR") != "" && os.Getenv("REDIS_PORT") != "" {
		rdo.Addr = fmt.Sprintf("%s:%s", os.Getenv("REDIS_ADDR"), os.Getenv("REDIS_PORT"))
	} else {
		rdo.Addr = "localhost:6379"
	}

	if conf.RedisPassword != "" {
		rdo.Password = conf.RedisPassword
	} else if os.Getenv("REDIS_PASSWORD") != "" {
		rdo.Password = os.Getenv("REDIS_PASSWORD")
	}

	log.Println("Connecting To Redis Server", rdo.Addr, "with db", rdo.DB, "with password", rdo.Password)

	rdb := redis.NewClient(rdo)
	defer rdb.Close()
	//Try to connect to the redis server
	if err = rdb.Ping(ctx).Err(); err != nil {
		log.Fatal("Fail to connect to redis")
	}

	log.Println("Connection Successful!")

	sig := make(chan struct{})
	router := httprouter.New()
	C := &Captcha{
		cache:  rdb,
		secret: conf.Secret,
	}
	router.GET("/captcha", C.GenCaptcha)
	router.GET("/captcha/:captcha_id/submitStatus", C.SubmitStatus)
	router.GET("/captcha/:captcha_id/submitResult", C.HandleCaptcha)
	router.GET("/captcha/:captcha_id/checkSubmitStatus", C.CheckSubmitStatus)

	RealListenPort := conf.ListenPort
	if RealListenPort == "" {
		if os.Getenv("PORT") != "" {
			RealListenPort = os.Getenv("PORT")
		} else {
			RealListenPort = "8080"
		}
	}

	log.Println("Listening on", conf.ListenAddr, "with port", RealListenPort)

	srv := &http.Server{
		Handler: router,
		Addr:    fmt.Sprintf("%s:%s", conf.ListenAddr, RealListenPort),
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
