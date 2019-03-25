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
    //使用refresh token换取access token
    RequestRefreshTokenEvent
    RequestAccessTokenEvent
    //验证token
    AuthenticateToken
    //废弃token
    RevokeToken
)

const (
    AuthorizationCodeExpireTime = 1 * time.Minute
    AccessTokenExpireTime       = 2 * time.Hour
    RefreshTokenExpireTime      = 30 * 24 * time.Hour
    TokenKeepExpireTime         = 5 * time.Minute
)

type ClientInfo struct {
    ClientId     string `json:"client_id"`
    ClientSecret string `json:"client_secret"`
}

type Token struct {
    AccessToken  string `json:"access_token,omitempty"`
    RefreshToken string `json:"refresh_token,omitempty"`
    TokenType    string `json:"token_type,omitempty"`
    ExpiresIn    int    `json:"expires_in,omitempty"`
    Scope        string `json:"scope,omitempty"`
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
    //初始化
    Init()
    //关闭
    Close()
    //设置一个值，含过期时间
    Set(key, value string, duration time.Duration) error
    //根据key获取value
    Get(key string) (string, error)
    //删除key
    Del(key string) error
    //根据key设置key过期时间
    SetExpire(key string, expireIn time.Duration) error
    //获得key过期时间
    TTL(key string) (time.Duration, error)
    //开启事务
    Multi() error
    //执行事务
    Exec() error
}

type EventListener func(clientId string, eventType int) *ErrCode
