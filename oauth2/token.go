package oauth2

import (
    "errors"
    "github.com/dgrijalva/jwt-go"
    "time"
)

func generateToken(client_id string, client_secret string, expire_time time.Duration) (string, error) {
    param := map[string]string{
        "client_id" : client_id,
    }
    return generateTokenWithParam(client_secret, expire_time, param)
}

func generateTokenWithParam(client_secret string, expire_time time.Duration, param map[string]string) (string, error) {
    now := time.Now()
    claims := jwt.MapClaims{
        "iat": now.Unix(),
        "exp": now.Add(expire_time).Unix(),
    }
    for k, v := range param {
        claims[k] = v
    }
    token := jwt.NewWithClaims(
        jwt.SigningMethodHS256,
        claims)

    return token.SignedString([]byte(client_secret))
}

func parseToken(client_secret string, token string) (string, error) {
    jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (i interface{}, e error) {
        return []byte(client_secret), nil
    })

    if err != nil {
        return "", err
    }

    if !jwtToken.Valid {
        return "", err
    }

    claims, ok := jwtToken.Claims.(jwt.MapClaims)
    if !ok {
        return "", errors.New("parse jwt error")
    }
    return claims["client_id"].(string), nil
}
