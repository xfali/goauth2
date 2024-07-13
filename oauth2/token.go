package oauth2

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/xfali/goutils/idUtil"
	"time"
)

const (
	TokenClaimKeyClientId = "client_id"
	TokenClaimKeyUsername = "username"
	TokenClaimKeyScope    = "scope"
)

func generateToken(client_id string, client_secret string, expire_time time.Duration, params ...map[string]string) (string, error) {
	var paramMap map[string]string
	if len(params) > 0 {
		paramMap = params[0]
		paramMap[TokenClaimKeyClientId] = client_id
	} else {
		paramMap = map[string]string{
			TokenClaimKeyClientId: client_id,
		}
	}
	return generateTokenWithParam(client_secret, expire_time, paramMap)
}

func generateTokenWithParam(client_secret string, expire_time time.Duration, param map[string]string) (string, error) {
	now := time.Now()
	nonce := idUtil.RandomId(6)
	claims := jwt.MapClaims{
		"iat":   now.Unix(),
		"exp":   now.Add(expire_time).Unix(),
		"nonce": nonce,
	}
	for k, v := range param {
		claims[k] = v
	}
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		claims)

	return token.SignedString([]byte(client_secret))
}

func parseTokenClaims(client_secret string, token string) (map[string]interface{}, error) {
	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (i interface{}, e error) {
		return []byte(client_secret), nil
	})

	if err != nil {
		return nil, err
	}

	if !jwtToken.Valid {
		return nil, err
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("parse jwt error")
	}
	return claims, nil
}

func parseToken(client_secret string, token string) (string, error) {
	m, err := parseTokenClaims(client_secret, token)
	if err != nil {
		return "", err
	}
	return m[TokenClaimKeyClientId].(string), nil
}
