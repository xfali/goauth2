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
    QuerySecret(client_id string) (string, error)

    //根据client_id刷新client_secret
    UpdateClient(client_id string) (string, error)

    //删除client_id及client_secret
    DeleteClient(client_id string) error

    //查询client_id是否可授权scope，可授权返回true
    CheckScope(client_id string, scope string) bool
}

type UserManager interface {
    //验证用户名和密码
    CheckUser(username, password string) error

    //创建用户
    CreateUser(username, password string) error
}

type DataManager interface {
    //初始化
    Init()

    //关闭
    Close()

    //保存Code相关信息，绑定client_id以及scope，在expireIn时间之后自动失效
    SaveCode(code, client_id, scope string, expireIn time.Duration) error

    //通过code获得client_id以及scope
    GetCode(code string) (string, string, error)

    //删除code
    DelCode(code string) error

    //保存refresh token
    SaveRefreshToken(token_data string, refresh_token string, refresh_expire time.Duration) error

    //保存refresh token以及access_token
    SaveAccessToken(token_data string, access_token string, access_expire time.Duration) error

    //通过refresh token获取保存的token data
    GetRefreshToken(refresh_token string) (string, error)

    //通过access token获取保存的token data
    GetAccessToken(access_token string) (string, error)

    //废弃client_id绑定的token，包括refresh token及access token
    RevokeToken(client_id string)
}

type EventListener func(clientId string, eventType int) *ErrCode
