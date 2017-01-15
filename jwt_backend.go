package tpi_auth

import (
	//"api.jwt.auth/core/redis"
	//"api.jwt.auth/services/models"
	//"api.jwt.auth/settings"
	"bufio"
	//"code.google.com/p/go-uuid/uuid"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	jwt "github.com/dgrijalva/jwt-go"
	request "github.com/dgrijalva/jwt-go/request"
	"github.com/stratadigm/tpi_data"
	"github.com/stratadigm/tpi_settings"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
	_ "google.golang.org/appengine/log"
	"net/http"
	"os"
	"time"
)

type JWTAuthenticationBackend struct {
	privateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

type TPIClaims struct {
	*jwt.StandardClaims
	UserInfo
}

type UserInfo struct {
	Email string
	Type  string
}

const (
	tokenDuration = 10 //seconds
	expireOffset  = 20 //seconds
)

var authBackendInstance *JWTAuthenticationBackend = nil

func InitJWTAuthenticationBackend() *JWTAuthenticationBackend {
	if authBackendInstance == nil {
		authBackendInstance = &JWTAuthenticationBackend{
			privateKey: getPrivateKey(),
			PublicKey:  getPublicKey(),
		}
	}

	return authBackendInstance
}

func (backend *JWTAuthenticationBackend) GenerateToken(userId string) (tpi_data.AuthToken, error) {
	token := jwt.New(jwt.SigningMethodRS512)

	token.Claims = &TPIClaims{
		&jwt.StandardClaims{
			// set the expire time
			// see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4.1.4
			ExpiresAt: time.Now().Add(time.Second * tokenDuration).Unix(),
			//ExpiresAt: time.Now().Add(time.Hour * time.Duration(tpi_settings.Get().JWTExpirationDelta)).Unix(),
		},
		UserInfo{userId, "Contributor"},
	}
	tokenString, err := token.SignedString(backend.privateKey)
	if err != nil {
		panic(err)
		return tpi_data.AuthToken{""}, err
	}
	return tpi_data.AuthToken{tokenString}, nil
}

//func (backend *JWTAuthenticationBackend) Authenticate(c context.Context, user *tpi_data.User) bool {
func (backend *JWTAuthenticationBackend) Authenticate(testUser *tpi_data.User, user *tpi_data.User) bool {

	return user.Email == testUser.Email && bcrypt.CompareHashAndPassword([]byte(testUser.Password), []byte(user.Password)) == nil
}

func (backend *JWTAuthenticationBackend) RefreshToken(req *http.Request) (tpi_data.AuthToken, error) {

	token, err := request.ParseFromRequestWithClaims(req, request.OAuth2Extractor, &TPIClaims{}, func(token *jwt.Token) (interface{}, error) {
		return backend.PublicKey, nil
	})
	if err != nil {
		temp := ""
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				if claims, ok1 := token.Claims.(*TPIClaims); ok1 {
					if time.Now().Sub(time.Unix(claims.StandardClaims.ExpiresAt, 0)).Seconds() < expireOffset {
						temp += "me"
						newToken, err := backend.GenerateToken(claims.UserInfo.Email)
						if err != nil {
							return tpi_data.AuthToken{""}, err
						}
						return newToken, nil
					}
				}
			}
		}
		return tpi_data.AuthToken{""}, err
	}
	if token.Valid {
		if claims, ok := token.Claims.(*TPIClaims); ok {
			newToken, err := backend.GenerateToken(claims.UserInfo.Email)
			if err != nil {
				return tpi_data.AuthToken{""}, err
			}
			return newToken, nil
		}
	}
	return tpi_data.AuthToken{""}, tpi_data.DSErr{When: time.Now(), What: "refresh token unknown "}

}

func (backend *JWTAuthenticationBackend) getTokenRemainingValidity(timestamp interface{}) int64 {
	if validity, ok := timestamp.(int64); ok {
		tm := time.Unix(validity, 0)
		remainer := tm.Sub(time.Now())
		if remainer > 0 {
			return int64(remainer.Seconds()) + expireOffset
		}
	}
	return expireOffset
}

//func (backend *JWTAuthenticationBackend) Logout(tokenString string, token *jwt.Token) error {
func (backend *JWTAuthenticationBackend) Logout(req *http.Request) (string, error) {

	token, err := request.ParseFromRequestWithClaims(req, request.OAuth2Extractor, &TPIClaims{}, func(token *jwt.Token) (interface{}, error) {
		return backend.PublicKey, nil
	})
	if err != nil {
		//log.Errorf(c, "auth logout parse token from req: %v\n", err)
		return "", err
	}
	if token.Valid { // valid unexpired token needs to be black listed after logout
		if _, ok := token.Claims.(*TPIClaims); ok {
			return token.Raw, nil
		}
		return token.Raw, nil
	}
	return "", nil

}

func (backend *JWTAuthenticationBackend) IsInBlacklist(c context.Context, token string) bool {

	adsc := tpi_data.NewDSwc(c)
	if err := adsc.GetToken(token); err != nil {
		return false
	}
	return true

}

func getPrivateKey() *rsa.PrivateKey {
	privateKeyFile, err := os.Open(tpi_settings.Get().PrivateKeyPath)
	if err != nil {
		panic(err)
	}

	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)

	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)

	data, _ := pem.Decode([]byte(pembytes))

	privateKeyFile.Close()

	privateKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)

	if err != nil {
		panic(err)
	}

	return privateKeyImported
}

func getPublicKey() *rsa.PublicKey {
	publicKeyFile, err := os.Open(tpi_settings.Get().PublicKeyPath)
	if err != nil {
		panic(err)
	}

	pemfileinfo, _ := publicKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)

	buffer := bufio.NewReader(publicKeyFile)
	_, err = buffer.Read(pembytes)

	data, _ := pem.Decode([]byte(pembytes))

	publicKeyFile.Close()

	publicKeyImported, err := x509.ParsePKIXPublicKey(data.Bytes)

	if err != nil {
		panic(err)
	}

	rsaPub, ok := publicKeyImported.(*rsa.PublicKey)

	if !ok {
		panic(err)
	}

	return rsaPub
}
