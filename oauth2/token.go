package oauth2

import (
    "errors"
    "github.com/dgrijalva/jwt-go"
    "time"
)

func generateToken(client_id, client_secret string, expire_time time.Duration) (string, error) {
    token := jwt.NewWithClaims(
        jwt.SigningMethodHS256,
        jwt.MapClaims{"client_id": client_id, "exp": time.Now().Add(expire_time).Unix()})
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
