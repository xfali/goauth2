/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package buildin

import (
    "github.com/xfali/goutils/container/recycleMap"
    "github.com/xfali/oauth2/defines"
    "strings"
    "time"
)

const (
    authorization_code_prefix   = "authorization_code:"
    access_token_prefix         = "access_token:"
    refresh_token_prefix        = "refresh_token:"
    client_access_token_prefix  = "client_access_token:"
    client_refresh_token_prefix = "client_refresh_token:"
)

type DefaultDataManager struct {
    recycleMap *recycleMap.RecycleMap
}

func NewDefaultDataManager(PurgeInterval time.Duration) *DefaultDataManager {
    ret := &DefaultDataManager{
        recycleMap: recycleMap.New(),
    }

    ret.recycleMap.PurgeInterval = PurgeInterval
    ret.recycleMap.Run()

    return ret
}

func (dm *DefaultDataManager) Init() {

}

func (dm *DefaultDataManager) Close() {
    dm.recycleMap.Close()
}

func (dm *DefaultDataManager) SaveCode(client_id, code, scope string, expireIn time.Duration) error {
    data := client_id + ":" + scope
    dm.recycleMap.Set(authorization_code_prefix+code, data, expireIn)
    return nil
}

//通过code获得client_id以及scope
func (dm *DefaultDataManager) GetCode(code string) (string, string, error) {
    data := dm.recycleMap.Get(authorization_code_prefix + code)
    if data == nil {
        return "", "", defines.CODE_IS_INVALID
    } else {
        strArr := strings.Split(data.(string), ":")
        if len(strArr) > 1 {
            return strArr[0], strArr[1], nil
        } else {
            return strArr[0], "", nil
        }
    }
}

//删除code
func (dm *DefaultDataManager) DelCode(code string) error {
    dm.recycleMap.Del(authorization_code_prefix + code)
    return nil
}

//保存refresh token
func (dm *DefaultDataManager) SaveRefreshToken(token_data string, refresh_token string, refresh_expire time.Duration) error {
    if refresh_token != "" {
        dm.recycleMap.Multi()
        old_refresh_token := dm.recycleMap.Get(client_refresh_token_prefix + token_data)
        if old_refresh_token != nil {
            ttl := dm.recycleMap.TTL(old_refresh_token)
            if ttl > defines.TokenKeepExpireTime {
                dm.recycleMap.SetExpire(old_refresh_token, defines.TokenKeepExpireTime)
            }
        }
        refresh_token = refresh_token_prefix + refresh_token
        dm.recycleMap.Set(refresh_token, token_data, refresh_expire)
        dm.recycleMap.Set(client_refresh_token_prefix+token_data, refresh_token, refresh_expire)
        return dm.recycleMap.Exec()
    }

    return defines.SAVE_REFRESHTOKEN_ERROR
}

//保存refresh token以及access_token
func (dm *DefaultDataManager) SaveAccessToken(token_data string, access_token string, access_expire time.Duration) error {
    if access_token != "" {
        dm.recycleMap.Multi()
        old_refresh_token := dm.recycleMap.Get(client_access_token_prefix + token_data)
        if old_refresh_token != nil {
            ttl := dm.recycleMap.TTL(old_refresh_token)
            if ttl > defines.TokenKeepExpireTime {
                dm.recycleMap.SetExpire(old_refresh_token, defines.TokenKeepExpireTime)
            }
        }
        access_token = access_token_prefix + access_token
        dm.recycleMap.Set(access_token, token_data, access_expire)
        dm.recycleMap.Set(client_access_token_prefix+token_data, access_token, access_expire)
        return dm.recycleMap.Exec()
    }

    return defines.SAVE_ACCESSTOKEN_ERROR
}

//通过refresh token获取保存的token data
func (dm *DefaultDataManager) GetRefreshToken(refresh_token string) (string, error) {
    data := dm.recycleMap.Get(refresh_token_prefix + refresh_token)
    if data == nil {
        return "", defines.REFRESH_TOKEN_NOT_FOUND
    } else {
        return data.(string), nil
    }
}

//通过access token获取保存的token data
func (dm *DefaultDataManager) GetAccessToken(access_token string) (string, error) {
    data := dm.recycleMap.Get(access_token_prefix + access_token)
    if data == nil {
        return "", defines.REFRESH_TOKEN_NOT_FOUND
    } else {
        return data.(string), nil
    }
}

//废弃client_id绑定的token，包括refresh token及access token
func (dm *DefaultDataManager) RevokeToken(client_id string) {
    dm.recycleMap.Multi()
    refresh_token := dm.recycleMap.Get(client_refresh_token_prefix + client_id)
    if refresh_token != nil {
        dm.recycleMap.Del(refresh_token)
        dm.recycleMap.Del(client_refresh_token_prefix + client_id)
    }
    access_token := dm.recycleMap.Get(client_access_token_prefix + client_id)
    if access_token != nil {
        dm.recycleMap.Del(access_token)
        dm.recycleMap.Del(client_access_token_prefix + client_id)
    }
    dm.recycleMap.Exec()
}
