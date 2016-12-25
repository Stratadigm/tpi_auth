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
	"github.com/stratadigm/tpi_data"
	"github.com/stratadigm/tpi_settings"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
	"os"
	"time"
)

type JWTAuthenticationBackend struct {
	privateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

const (
	tokenDuration = 72
	expireOffset  = 3600
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

	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour * time.Duration(tpi_settings.Get().JWTExpirationDelta)).Unix()
	claims["iat"] = time.Now().Unix()
	claims["sub"] = userId
	token.Claims = claims
	tokenString, err := token.SignedString(backend.privateKey)
	if err != nil {
		panic(err)
		return tpi_data.AuthToken{""}, err
	}
	return tpi_data.AuthToken{tokenString}, nil
}

func (backend *JWTAuthenticationBackend) Authenticate(c context.Context, user *tpi_data.User) bool {
	/*hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testing"), 10)

	testUser := models.User{
		UUID:     uuid.New(),
		Username: "haku",
		Password: string(hashedPassword),
	}*/
	adsc := tpi_data.NewDSwc(c) //&tpi_data.DS{Ctx: c}
	testUser, err := adsc.GetUserwEmail(user.Email)
	if err != nil {
		return false
	}

	return user.Email == testUser.Email && bcrypt.CompareHashAndPassword([]byte(testUser.Password), []byte(user.Password)) == nil
}

func (backend *JWTAuthenticationBackend) getTokenRemainingValidity(timestamp interface{}) int {
	if validity, ok := timestamp.(float64); ok {
		tm := time.Unix(int64(validity), 0)
		remainer := tm.Sub(time.Now())
		if remainer > 0 {
			return int(remainer.Seconds() + expireOffset)
		}
	}
	return expireOffset
}

func (backend *JWTAuthenticationBackend) Logout(tokenString string, token *jwt.Token) error {
	//redisConn := redis.Connect()
	//return redisConn.SetValue(tokenString, tokenString, backend.getTokenRemainingValidity(token.Claims["exp"]))
	return nil
}

func (backend *JWTAuthenticationBackend) IsInBlacklist(c context.Context, token string) bool {
	//redisConn := redis.Connect()
	//redisToken, _ := redisConn.GetValue(token)

	//if redisToken == nil {
	//	return false
	//}
	adsc := tpi_data.NewDSwc(c)
	tok, err := adsc.GetToken(token)
	if tok == "" || err != nil {
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
