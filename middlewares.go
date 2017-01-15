package tpi_auth

import (
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	request "github.com/dgrijalva/jwt-go/request"
	"google.golang.org/appengine"
	"google.golang.org/appengine/log"
	"net/http"
)

func RequireTokenAuthentication(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {

	c := appengine.NewContext(req)
	authBackend := InitJWTAuthenticationBackend()

	//token, err := jwt.ParseFromRequest(req, func(token *jwt.Token) (interface{}, error) {
	//token, err := request.ParseFromRequest(req, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
	token, err := request.ParseFromRequestWithClaims(req, request.OAuth2Extractor, &TPIClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			log.Errorf(c, "RequireTokenAuthentication parse !ok ")
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		} else {
			return authBackend.PublicKey, nil
		}
	})

	if err == nil && token.Valid && !authBackend.IsInBlacklist(c, token.Raw) {
		next(rw, req)
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			log.Errorf(c, "malformed token %v %v", token, err)
			rw.WriteHeader(http.StatusUnauthorized)
			return
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			// Token is either expired or not active yet
			log.Errorf(c, "expired/future token %v %v", token, err)
			rw.WriteHeader(http.StatusUnauthorized)
			return
		} else {
			log.Errorf(c, "unknown token %v %v", token, err)
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
	} else {
		log.Errorf(c, "blacklisted token %v %v", token, err)
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

}
