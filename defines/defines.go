/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package defines

import "time"

const (
    //Authorization Code类型授权（网页授权）事件
    AuthorizationCodeEvent = iota
    //使用Authorization Code换取Token事件
    AuthorizationCodeTokenEvent
    //Implicit类型授权（简易网页授权）事件
    ImplicitEvent
    //使用client_id、client_secret及username、password换取Token事件
    PasswordTokenEvent
    //使用client_id、client_secret换取Token事件
    ClientCredentialsTokenEvent
    RequestRefreshTokenEvent
    RequestAccessTokenEvent
)

const (
    AccessTokenExpireTime  = 2 * time.Hour
    RefreshTokenExpireTime = 30 * 24 * time.Hour
)

type ClientInfo struct {
    ClientId     string `json:"client_id"`
    ClientSecret string `json:"client_secret"`
}

type Token struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
    Scope        string `json:"scope"`
}

type ClientManager interface {
    //创建client，返回client_id及client_secret
    CreateClient() (ClientInfo, error)
    //根据client_id查询client_secret
    QuerySecret(string) (string, error)
    //根据client_id刷新client_secret
    UpdateClient(string) (string, error)
    //删除client_id及client_secret
    DeleteClient(string) error
}

type UserManager interface {
    //验证用户名和密码
    CheckUser(username, password string) error
}

type DataManager interface {
    Set(key, value string, duration time.Duration) error
    Get(key string) (string, error)
    Del(key string) error
    Close()
}

type EventListener func(clientId string, eventType int) *ErrCode
