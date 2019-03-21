/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package defines

import "time"

const(
    //Authorization Code类型授权（网页授权）事件
    AuthorizationCodeEvent = iota
    RequestRefreshTokenEvent
    RequestAccessTokenEvent
)

type ClientInfo struct {
    ClientId     string `json:"client_id"`
    ClientSecret string `json:"client_secret"`
}

type Token struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int `json:"expires_in"`
    Scope        string `json:"scope"`
}

type ClientManager interface {
    CreateClient() (ClientInfo, error)
    QuerySecret(string) (string, error)
    UpdateClient(string) (string, error)
    DeleteClient(string) error
}

type DataManager interface {
    Set(key, value string, duration time.Duration) error
    Get(key string) (string, error)
    Del(key string) error
    Close()
}

type EventListener func(clientId string, eventType int) *ErrCode
