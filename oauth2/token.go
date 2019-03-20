package oauth2

import "github.com/xfali/goid"

func generateToken(client_id string) string {
    return goid.RandomId(32)
}
