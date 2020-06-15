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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
)

const (
	constBankCode              = "200"
	constTokenKey              = "RAHASIA"
	constAPIKey                = "dev_akey_U1AQQ7Z1PP"
	constValidationKey         = "dev_vkey_VPT6U7M3HC"
	constDefaultURLInquiry     = "http://localhost:8081/process-va"
	constDefaultURLPayment     = "http://localhost:8081/process-va"
	constDefaultURLCheckStatus = "http://localhost:8081/process-va"

	responseCodeSuccess        = "00"
	responseCodeFailed         = "01"

	responseTextSuccess        = "Success"
	responseTextFailed         = "Failed"

	defaultCurrencyCode        = "IDR"
)

func main() {

	
	/**
	 * Token handler
	 */
	http.HandleFunc("/bank/auth/token/", tokenHandler)
	
	/**
	 * Inquiry handler
	 */
	 http.Handle("/bank/va/inquiry/", authMiddleware(http.HandlerFunc(inquiryHandler)))
	
	/**
	 * Payment handler
	 */
	http.Handle("/bank/va/payment/", authMiddleware(http.HandlerFunc(paymentHandler)))
	
	/**
	 * Check status handler
	 */
    http.Handle("/bank/va/check-status/", authMiddleware(http.HandlerFunc(checkStatusHandler)))

    if err := http.ListenAndServe(":8013", nil); err != nil {
        log.Fatal(err)
    }
}


// TokenHandler is our handler to take a username and password and,
// if it's valid, return a token used for future requests.
func tokenHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Add("Content-Type", "application/json")
    r.ParseForm()

    // Check the credentials provided - if you store these in a database then
	// this is where your query would go to check.
	
	auth := r.Header.Get("Authorization");
	userpassEnc := strings.SplitN(auth, " ", 2)
	base64String := userpassEnc[1]
	sDec,_ := base64.StdEncoding.DecodeString(base64String)
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
    tokenString, err := token.SignedString([]byte(constTokenKey))
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
func authMiddleware(next http.Handler) http.Handler {
    if len(constTokenKey) == 0 {
        log.Fatal("HTTP server unable to start, expected an constTokenKey for JWT auth")
    }
    jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
        ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
            return []byte(constTokenKey), nil
        },
        SigningMethod: jwt.SigningMethodHS256,
    })
    return jwtMiddleware.Handler(next)
}
func createSignature(httpMethod string, path string, token string, timeStamp string, body string) string{
	validationKey := os.Getenv("VA_VALIDATION_KEY")
	if len(validationKey) == 0{
		validationKey = constValidationKey
	}
	regexSpace := regexp.MustCompile(`\s+`)
	canonicalBody := regexSpace.ReplaceAllString(body, "")
	h := sha256.New()
	h.Write([]byte(canonicalBody))
	sha := h.Sum(nil) 
	sha256Body := hex.EncodeToString(sha)
	stringToSign := fmt.Sprintf("%s:%s:%s:%s:%s", httpMethod, path, token, sha256Body, timeStamp)
	hash := hmac.New(sha256.New, []byte(validationKey))
	io.WriteString(hash, stringToSign)
	signtaure := fmt.Sprintf("%x", hash.Sum(nil))
	return signtaure
}
func inquiryHandler(w http.ResponseWriter, r *http.Request) {
	timeStamp := time.Now().UTC().Format(time.RFC3339Nano)
	timeStamp = string(timeStamp[0:23]) + "Z"
	bankCode := os.Getenv("VA_BANK_CODE")
	if len(bankCode) == 0{
		bankCode = constBankCode
	}
	urlInquiry := os.Getenv("VA_URL_INQUIRY")
	if len(urlInquiry) == 0{
		urlInquiry = constDefaultURLInquiry
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
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}
	signature1 := createSignature(r.Method, r.RequestURI, token, r.Header.Get("x-bank-timestamp"), string(reqBody))
	signature2 := r.Header.Get("x-bank-signature")
	if(signature1 != signature2){
		log.Printf("Invalid signature")
		http.Error(w, "Can't read body", http.StatusBadRequest)
		return
	}

	var jsonRequest map[string]interface{}
	json.Unmarshal([]byte(reqBody), &jsonRequest)

	// Add bank code
	jsonRequest["data"].(map[string]interface{})["bank_code"] = bankCode

	bufRequest, _ := json.Marshal(jsonRequest)
	
	response, err := http.Post(urlInquiry, "application/json", bytes.NewBuffer(bufRequest))
	
	var responseBody string
	var responseCode string
	var responseText string

	if err != nil{
		log.Println("Terjadi error di sini")

		var jsonResponse map[string]interface{}
		json.Unmarshal([]byte(reqBody), &jsonResponse)

		delete(jsonResponse["data"].(map[string]interface{}), "date_time")
		jsonResponse["data"].(map[string]interface{})["time_stamp"] = timeStamp
		jsonResponse["data"].(map[string]interface{})["currency_code"] = defaultCurrencyCode
		jsonResponse["data"].(map[string]interface{})["customer_name"] = ""
		jsonResponse["data"].(map[string]interface{})["customer_email"] = ""
		jsonResponse["data"].(map[string]interface{})["customer_phone"] = ""
		jsonResponse["data"].(map[string]interface{})["merchant_code"] = ""
		jsonResponse["data"].(map[string]interface{})["merchant_name"] = ""

		jsonResponse["data"].(map[string]interface{})["bill_list"] = make([]string, 0)

		// Delete pg_code from client
		delete(jsonResponse["data"].(map[string]interface{}), "pg_code")
		jsonResponse["response_code"] = responseCodeFailed
		jsonResponse["response_text"] = responseTextFailed

		bufResponse, _ := json.Marshal(jsonResponse)
		responseBody = string(bufResponse)
	}else{
		responseFromService, empty := ioutil.ReadAll(response.Body)
		var jsonResponse map[string]interface{}
		if empty != nil{
			json.Unmarshal([]byte(reqBody), &jsonResponse)
		}else{
			json.Unmarshal([]byte(responseFromService), &jsonResponse)

			if str, ok:= jsonResponse["response_code"].(string); ok{
				responseCode = str;
			}else{
				fmt.Println("Ga dapat response code di sini")
				json.Unmarshal([]byte(reqBody), &jsonResponse)
				delete(jsonResponse["data"].(map[string]interface{}), "date_time")
				jsonResponse["data"].(map[string]interface{})["time_stamp"] = timeStamp
				jsonResponse["data"].(map[string]interface{})["currency_code"] = defaultCurrencyCode
				jsonResponse["data"].(map[string]interface{})["customer_name"] = ""
				jsonResponse["data"].(map[string]interface{})["customer_email"] = ""
				jsonResponse["data"].(map[string]interface{})["customer_phone"] = ""
				jsonResponse["data"].(map[string]interface{})["merchant_code"] = ""
				jsonResponse["data"].(map[string]interface{})["merchant_name"] = ""		
				jsonResponse["data"].(map[string]interface{})["bill_list"] = make([]string, 0)
				responseCode = responseCodeFailed
			}
			if str, ok:= jsonResponse["response_text"].(string); ok{
				responseText = str;
			}else{
				responseText = responseTextFailed
			}
		}

		jsonResponse["response_code"] = responseCode
		jsonResponse["response_text"] = responseText

		// Delete pg_code and bank_code from client
		delete(jsonResponse["data"].(map[string]interface{}), "pg_code")
		delete(jsonResponse["data"].(map[string]interface{}), "bank_code")
		
		// Delete log_data from client
		delete(jsonResponse, "log_data")

		bufResponse, _ := json.Marshal(jsonResponse)
		responseBody = string(bufResponse)
	}
	io.WriteString(w, responseBody)
	
}

func paymentHandler(w http.ResponseWriter, r *http.Request) {
    timeStamp := time.Now().UTC().Format(time.RFC3339Nano)
	timeStamp = string(timeStamp[0:23]) + "Z"
	bankCode := os.Getenv("VA_BANK_CODE")
	if len(bankCode) == 0{
		bankCode = constBankCode
	}
	urlInquiry := os.Getenv("VA_URL_PAYMENT")
	if len(urlInquiry) == 0{
		urlInquiry = constDefaultURLPayment
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
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}
	signature1 := createSignature(r.Method, r.RequestURI, token, r.Header.Get("x-bank-timestamp"), string(reqBody))
	signature2 := r.Header.Get("x-bank-signature")
	if(signature1 != signature2){
		log.Printf("Invalid signature")
		http.Error(w, "Can't read body", http.StatusBadRequest)
		return
	}

	var jsonRequest map[string]interface{}
	json.Unmarshal([]byte(reqBody), &jsonRequest)

	// Add bank code
	jsonRequest["data"].(map[string]interface{})["bank_code"] = bankCode

	bufRequest, _ := json.Marshal(jsonRequest)
	
	response, err := http.Post(urlInquiry, "application/json", bytes.NewBuffer(bufRequest))
	
	var responseBody string
	var responseCode string
	var responseText string

	if err != nil{
		log.Println("Terjadi error di sini")

		var jsonResponse map[string]interface{}
		json.Unmarshal([]byte(reqBody), &jsonResponse)

		delete(jsonResponse["data"].(map[string]interface{}), "date_time")
		jsonResponse["data"].(map[string]interface{})["time_stamp"] = timeStamp
		jsonResponse["data"].(map[string]interface{})["currency_code"] = defaultCurrencyCode
		jsonResponse["data"].(map[string]interface{})["customer_name"] = ""
		jsonResponse["data"].(map[string]interface{})["customer_email"] = ""
		jsonResponse["data"].(map[string]interface{})["customer_phone"] = ""
		jsonResponse["data"].(map[string]interface{})["merchant_code"] = ""
		jsonResponse["data"].(map[string]interface{})["merchant_name"] = ""

		jsonResponse["data"].(map[string]interface{})["bill_list"] = make([]string, 0)

		// Delete pg_code from client
		delete(jsonResponse["data"].(map[string]interface{}), "pg_code")
		jsonResponse["response_code"] = responseCodeSuccess
		jsonResponse["response_text"] = responseTextSuccess

		bufResponse, _ := json.Marshal(jsonResponse)
		responseBody = string(bufResponse)
	}else{
		responseFromService, empty := ioutil.ReadAll(response.Body)
		var jsonResponse map[string]interface{}
		if empty != nil{
			json.Unmarshal([]byte(reqBody), &jsonResponse)
		}else{
			json.Unmarshal([]byte(responseFromService), &jsonResponse)

			if str, ok:= jsonResponse["response_code"].(string); ok{
				responseCode = str;
			}else{
				fmt.Println("Ga dapat response code di sini")
				json.Unmarshal([]byte(reqBody), &jsonResponse)
				delete(jsonResponse["data"].(map[string]interface{}), "date_time")
				jsonResponse["data"].(map[string]interface{})["time_stamp"] = timeStamp
				jsonResponse["data"].(map[string]interface{})["currency_code"] = defaultCurrencyCode
				jsonResponse["data"].(map[string]interface{})["customer_name"] = ""
				jsonResponse["data"].(map[string]interface{})["customer_email"] = ""
				jsonResponse["data"].(map[string]interface{})["customer_phone"] = ""
				jsonResponse["data"].(map[string]interface{})["merchant_code"] = ""
				jsonResponse["data"].(map[string]interface{})["merchant_name"] = ""		
				jsonResponse["data"].(map[string]interface{})["bill_list"] = make([]string, 0)
				responseCode = responseCodeSuccess
			}
			if str, ok:= jsonResponse["response_text"].(string); ok{
				responseText = str;
			}else{
				responseText = responseTextSuccess
			}
		}

		jsonResponse["response_code"] = responseCode
		jsonResponse["response_text"] = responseText

		// Delete pg_code and bank_code from client
		delete(jsonResponse["data"].(map[string]interface{}), "pg_code")
		delete(jsonResponse["data"].(map[string]interface{}), "bank_code")
		
		// Delete log_data from client
		delete(jsonResponse, "log_data")

		bufResponse, _ := json.Marshal(jsonResponse)
		responseBody = string(bufResponse)
	}
	io.WriteString(w, responseBody)
}

func checkStatusHandler(w http.ResponseWriter, r *http.Request) {
    timeStamp := time.Now().UTC().Format(time.RFC3339Nano)
	timeStamp = string(timeStamp[0:23]) + "Z"
	bankCode := os.Getenv("VA_BANK_CODE")
	if len(bankCode) == 0{
		bankCode = constBankCode
	}
	urlInquiry := os.Getenv("VA_URL_CHECK_STATUS")
	if len(urlInquiry) == 0{
		urlInquiry = constDefaultURLCheckStatus
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
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}
	signature1 := createSignature(r.Method, r.RequestURI, token, r.Header.Get("x-bank-timestamp"), string(reqBody))
	signature2 := r.Header.Get("x-bank-signature")
	if(signature1 != signature2){
		log.Printf("Invalid signature")
		http.Error(w, "Can't read body", http.StatusBadRequest)
		return
	}

	var jsonRequest map[string]interface{}
	json.Unmarshal([]byte(reqBody), &jsonRequest)

	// Add bank code
	jsonRequest["data"].(map[string]interface{})["bank_code"] = bankCode

	bufRequest, _ := json.Marshal(jsonRequest)
	
	response, err := http.Post(urlInquiry, "application/json", bytes.NewBuffer(bufRequest))
	
	var responseBody string
	var responseCode string
	var responseText string

	if err != nil{
		log.Println("Terjadi error di sini")

		var jsonResponse map[string]interface{}
		json.Unmarshal([]byte(reqBody), &jsonResponse)

		delete(jsonResponse["data"].(map[string]interface{}), "date_time")
		jsonResponse["data"].(map[string]interface{})["time_stamp"] = timeStamp
		jsonResponse["data"].(map[string]interface{})["currency_code"] = defaultCurrencyCode
		jsonResponse["data"].(map[string]interface{})["customer_name"] = ""
		jsonResponse["data"].(map[string]interface{})["customer_email"] = ""
		jsonResponse["data"].(map[string]interface{})["customer_phone"] = ""
		jsonResponse["data"].(map[string]interface{})["merchant_code"] = ""
		jsonResponse["data"].(map[string]interface{})["merchant_name"] = ""

		jsonResponse["data"].(map[string]interface{})["bill_list"] = make([]string, 0)

		// Delete pg_code from client
		delete(jsonResponse["data"].(map[string]interface{}), "pg_code")
		jsonResponse["response_code"] = responseCodeSuccess
		jsonResponse["response_text"] = responseTextSuccess

		bufResponse, _ := json.Marshal(jsonResponse)
		responseBody = string(bufResponse)
	}else{
		responseFromService, empty := ioutil.ReadAll(response.Body)
		var jsonResponse map[string]interface{}
		if empty != nil{
			json.Unmarshal([]byte(reqBody), &jsonResponse)
		}else{
			json.Unmarshal([]byte(responseFromService), &jsonResponse)

			if str, ok:= jsonResponse["response_code"].(string); ok{
				responseCode = str;
			}else{
				fmt.Println("Ga dapat response code di sini")
				json.Unmarshal([]byte(reqBody), &jsonResponse)
				delete(jsonResponse["data"].(map[string]interface{}), "date_time")
				jsonResponse["data"].(map[string]interface{})["time_stamp"] = timeStamp
				jsonResponse["data"].(map[string]interface{})["currency_code"] = defaultCurrencyCode
				jsonResponse["data"].(map[string]interface{})["customer_name"] = ""
				jsonResponse["data"].(map[string]interface{})["customer_email"] = ""
				jsonResponse["data"].(map[string]interface{})["customer_phone"] = ""
				jsonResponse["data"].(map[string]interface{})["merchant_code"] = ""
				jsonResponse["data"].(map[string]interface{})["merchant_name"] = ""		
				jsonResponse["data"].(map[string]interface{})["bill_list"] = make([]string, 0)
				responseCode = responseCodeSuccess
			}
			if str, ok:= jsonResponse["response_text"].(string); ok{
				responseText = str;
			}else{
				responseText = responseTextSuccess
			}
		}

		jsonResponse["response_code"] = responseCode
		jsonResponse["response_text"] = responseText

		// Delete pg_code and bank_code from client
		delete(jsonResponse["data"].(map[string]interface{}), "pg_code")
		delete(jsonResponse["data"].(map[string]interface{}), "bank_code")
		
		// Delete log_data from client
		delete(jsonResponse, "log_data")

		bufResponse, _ := json.Marshal(jsonResponse)
		responseBody = string(bufResponse)
	}
	io.WriteString(w, responseBody)
}
