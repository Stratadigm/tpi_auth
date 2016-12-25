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
	token, err := request.ParseFromRequest(req, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			log.Errorf(c, "RequireTokenAuthentication parse !OK ")
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		} else {
			return authBackend.PublicKey, nil
		}
	})

	if err == nil && token.Valid && !authBackend.IsInBlacklist(c, req.Header.Get("Authorization")) {
		next(rw, req)
	} else {
		log.Errorf(c, "RequireTokenAuthentication token %v %v", token, err)
		rw.WriteHeader(http.StatusUnauthorized)
	}
}
