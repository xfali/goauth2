/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package test

import (
    "fmt"
    "github.com/xfali/oauth2/oauth2"
    "testing"
)

func TestOauth2(t *testing.T) {
    auth := oauth2.New()
    ClientInfo, _ := auth.ClientManager.CreateClient()
    fmt.Printf("client_id: %s\n client_secret: %s\n", ClientInfo.ClientId, ClientInfo.ClientSecret)
    auth.Run(":8080")
}
