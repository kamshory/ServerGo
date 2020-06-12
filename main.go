package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"


	"github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"

	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
)

const (
	TokenKey = "RAHASIA"
	API_KEY = "dev_akey_U1AQQ7Z1PP"
	VALIDATION_KEY = "dev_vkey_VPT6U7M3HC"
	DEFAULT_URL_INQUIRY = "http://localhost:8888/bank/va/inquiry"
)

func main() {

	
	/**
	 * Token handler
	 */
	http.HandleFunc("/bank/auth/token/", TokenHandler)
	
	/**
	 * Inquiry handler
	 */
	 http.Handle("/bank/va/inquiry/", AuthMiddleware(http.HandlerFunc(InquiryHandler)))
	
	/**
	 * Payment handler
	 */
	http.Handle("/bank/va/payment", AuthMiddleware(http.HandlerFunc(PaymentHandler)))
	
	/**
	 * Check status handler
	 */
    http.Handle("/bank/va/check-status", AuthMiddleware(http.HandlerFunc(CheckStatusHandler)))

    if err := http.ListenAndServe(":8013", nil); err != nil {
        log.Fatal(err)
    }
}


// TokenHandler is our handler to take a username and password and,
// if it's valid, return a token used for future requests.
func TokenHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.Method)
    w.Header().Add("Content-Type", "application/json")
    r.ParseForm()

    // Check the credentials provided - if you store these in a database then
	// this is where your query would go to check.
	
	auth := r.Header.Get("Authorization");
	userpassEnc := strings.SplitN(auth, " ", 2)
	base64String := userpassEnc[1]
	sDec,_ := b64.StdEncoding.DecodeString(base64String)
	userpass := strings.SplitN(string(sDec), ":", 2)

	username := userpass[0]
	password := userpass[1]

    if username != "ad7e9a44-76bf-4369-9358-a9c560288217" || password != "041bea89-8a6b-4cd6-bf03-8d407c404d25" {
        w.WriteHeader(http.StatusUnauthorized)
        io.WriteString(w, `{"error":"invalid_credentials"}`)
        return
	}
	expire := time.Now().Add(time.Hour * time.Duration(1)).Unix()
    // We are happy with the credentials, so build a token. We've given it
    // an expiry of 1 hour.
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "user": username,
        "exp":  expire,
        "iat":  time.Now().Unix(),
    })
    tokenString, err := token.SignedString([]byte(TokenKey))
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        io.WriteString(w, `{"error":"token_generation_failed"}`)
        return
    }
    io.WriteString(w, `{"token_type":"Bearer","expires_in":3600,"access_token":"`+tokenString+`"}`)
    return
}

// AuthMiddleware is our middleware to check our token is valid. Returning
// a 401 status to the client if it is not valid.
func AuthMiddleware(next http.Handler) http.Handler {
    if len(TokenKey) == 0 {
        log.Fatal("HTTP server unable to start, expected an TokenKey for JWT auth")
    }
    jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
        ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
            return []byte(TokenKey), nil
        },
        SigningMethod: jwt.SigningMethodHS256,
    })
    return jwtMiddleware.Handler(next)
}
func CreateSignature(httpMethod string, path string, token string, timestamp string, body string) string{
	validationKey := os.Getenv("VALIDATION_KEY")
	if len(validationKey) == 0{
		validationKey = VALIDATION_KEY
	}
	regexSpace := regexp.MustCompile(`\s+`)
	canonicalBody := regexSpace.ReplaceAllString(body, "")
	h := sha256.New()
	h.Write([]byte(canonicalBody))
	sha := h.Sum(nil)  // "sha" is uint8 type, encoded in base16
	sha256Body := hex.EncodeToString(sha)
	stringToSign := fmt.Sprintf("%s:%s:%s:%s:%s", httpMethod, path, token, sha256Body, timestamp)
	log.Print(body)
	log.Print(canonicalBody)
	log.Print(sha256Body)
	log.Print(stringToSign)
	hash := hmac.New(sha256.New, []byte(validationKey))
	io.WriteString(hash, stringToSign)
	signtaure := fmt.Sprintf("%x", hash.Sum(nil))
	return signtaure
}
func InquiryHandler(w http.ResponseWriter, r *http.Request) {

	urlInquiry := os.Getenv("VA_URL_INQUIRY")
	if len(urlInquiry) == 0{
		urlInquiry = DEFAULT_URL_INQUIRY
	}
	token := r.Header.Get("Authorization")
	if len(token) > 7{
		token = string(token[7:])
	}
	w.Header().Add("Content-Type", "application/json")
	
	reqBody, err := ioutil.ReadAll(r.Body)
    if err != nil {
        log.Fatal(err)
    }
	fmt.Printf("%s", reqBody)
	
	fmt.Print(reqBody)

	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}
	signature1 := CreateSignature(r.Method, r.RequestURI, token, r.Header.Get("x-bank-timestamp"), string(reqBody))
	signature2 := r.Header.Get("x-bank-signature")
	fmt.Println("Signature Generated : "+signature1)
	fmt.Println("Signature Sent      : "+signature2)
	if(signature1 == signature2){
		log.Printf("Invalid signature")
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}

	jsonRequest := make(map[string]interface{})
	json.Unmarshal(reqBody, &jsonRequest)

	buf, _ := json.Marshal(jsonRequest)
	
	res, err := http.Post(urlInquiry, "application/json", bytes.NewBuffer(buf))
	data, _ := ioutil.ReadAll(res.Body)
	res.Body.Close()

	if res.Request.Response.Status == "200"{

	}
	fmt.Println(string(data))

    io.WriteString(w, `{"status":"ok", "command":"inquiry"}`)
}

func PaymentHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Add("Content-Type", "application/json")
    io.WriteString(w, `{"status":"ok", "command":"payment"}`)
}

func CheckStatusHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Add("Content-Type", "application/json")
    io.WriteString(w, `{"status":"ok", "command":"check-status"}`)
}
