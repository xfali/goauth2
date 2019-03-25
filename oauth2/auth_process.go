/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package oauth2

import (
    "encoding/base64"
    "github.com/xfali/oauth2/defines"
    "strings"
)

const (
    authorization_code_prefix   = "authorization_code:"
    access_token_prefix         = "access_token:"
    refresh_token_prefix        = "refresh_token:"
    client_access_token_prefix  = "client_access_token:"
    client_refresh_token_prefix = "client_refresh_token:"
)

func saveCode(dm defines.DataManager, client_id, code string) error {
    return dm.Set(authorization_code_prefix+code, client_id, defines.AuthorizationCodeExpireTime)
}

func getCode(dm defines.DataManager, code string) (string, error) {
    return dm.Get(code)
}

func delCode(dm defines.DataManager, code string) error {
    return dm.Del(code)
}

func saveToken(dm defines.DataManager, client_id, access_token, refresh_token string) {
    dm.Multi()
    if refresh_token != "" {
        old_refresh_token, err := dm.Get(client_refresh_token_prefix+client_id)
        if err == nil {
            ttl, _ := dm.TTL(old_refresh_token)
            if ttl > defines.TokenKeepExpireTime {
                dm.SetExpire(old_refresh_token, defines.TokenKeepExpireTime)
            }
        }
        dm.Set(refresh_token_prefix+refresh_token, client_id, defines.RefreshTokenExpireTime)
        dm.Set(client_refresh_token_prefix+client_id, refresh_token, defines.RefreshTokenExpireTime)
    }

    if access_token != "" {
        old_access_token, err := dm.Get(client_access_token_prefix+client_id)
        if err == nil {
            ttl, _ := dm.TTL(old_access_token)
            if ttl > defines.TokenKeepExpireTime {
                dm.SetExpire(old_access_token, defines.TokenKeepExpireTime)
            }
        }
        dm.Set(access_token_prefix+access_token, client_id, defines.AccessTokenExpireTime)
        dm.Set(client_access_token_prefix+client_id, access_token, defines.AccessTokenExpireTime)
    }
    dm.Exec()
}

func getRefreshToken(dm defines.DataManager, refresh_token string) (string, error) {
    return dm.Get(refresh_token_prefix + refresh_token)
}

func getAccessToken(dm defines.DataManager, access_token string) (string, error) {
    return dm.Get(access_token_prefix + access_token)
}

func parseBasicInfo(authorization string) (string, string, error) {
    basicStr := ""
    if len(authorization) > 5 && strings.ToUpper(authorization[0:6]) == "BASIC " {
        basicStr = authorization[6:]
    } else {
        basicStr = authorization
    }

    bytes, err := base64.StdEncoding.DecodeString(basicStr)
    if err != nil {
        return "", "", defines.AUTHORIZATION_BASIC_ERROR
    }

    basicStr = string(bytes)

    strs := strings.Split(basicStr, ":")
    if len(strs) < 2 {
        return "", "", defines.AUTHORIZATION_BASIC_ERROR
    }

    return strs[0], strs[1], nil
}

func parseBearerInfo(authorization string) (string, error) {
    bearerStr := ""
    if len(authorization) > 6 && strings.ToUpper(authorization[0:7]) == "BEARER " {
        bearerStr = authorization[7:]
    } else {
        bearerStr = authorization
    }
    return bearerStr, nil
}
