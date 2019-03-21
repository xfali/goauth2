package oauth2

import (
    "github.com/dgrijalva/jwt-go"
    "time"
)

func generateToken(client_id, client_secret string, expire_time time.Duration) (string, error) {
    token := jwt.NewWithClaims(
        jwt.SigningMethodHS256,
        jwt.MapClaims{"client_id": client_id, "exp": time.Now().Add(expire_time).Unix()})
    return token.SignedString(client_secret)
}
