/*
 * Copyright (C) 2019-2024, Xiongfa Li.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package datas

import (
	"github.com/xfali/goutils/container/recycleMap"
	"github.com/xfali/oauth2/v2/constants"
	"github.com/xfali/oauth2/v2/errcodes"
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
	recycleMap recycleMap.RecycleMap
}

func NewDefaultDataManager(PurgeInterval time.Duration) *DefaultDataManager {
	ret := &DefaultDataManager{
		recycleMap: recycleMap.New(recycleMap.OptSetPurgeInterval(PurgeInterval)),
	}

	return ret
}

func (dm *DefaultDataManager) Init() {

}

func (dm *DefaultDataManager) Close() {
	dm.recycleMap.Close()
}

func (dm *DefaultDataManager) SaveCode(code, token string, expireIn time.Duration) error {
	dm.recycleMap.Set(authorization_code_prefix+code, token, expireIn)
	return nil
}

//通过code获得client_id以及scope
func (dm *DefaultDataManager) GetCode(code string) (string, error) {
	data := dm.recycleMap.Get(authorization_code_prefix + code)
	if data == nil {
		return "", errcodes.CodeIsInvalid
	} else {
		return data.(string), nil
		//strArr := strings.Split(data.(string), ":")
		//if len(strArr) > 1 {
		//	return strArr[0], strArr[1], nil
		//} else {
		//	return strArr[0], "", nil
		//}
	}
}

//删除code
func (dm *DefaultDataManager) DelCode(code string) error {
	dm.recycleMap.Delete(authorization_code_prefix + code)
	return nil
}

//保存refresh token
func (dm *DefaultDataManager) SaveRefreshToken(token_data string, refresh_token string, refresh_expire time.Duration) error {
	if refresh_token != "" {
		//_ = dm.recycleMap.Multi()
		//defer dm.recycleMap.Exec()
		old_refresh_token := dm.recycleMap.Get(client_refresh_token_prefix + token_data)
		if old_refresh_token != nil {
			ttl := dm.recycleMap.TTL(old_refresh_token)
			if ttl > constants.TokenKeepExpireTime {
				dm.recycleMap.SetExpire(old_refresh_token, constants.TokenKeepExpireTime)
			}
		}
		refresh_token = refresh_token_prefix + refresh_token
		dm.recycleMap.Set(refresh_token, token_data, refresh_expire)
		dm.recycleMap.Set(client_refresh_token_prefix+token_data, refresh_token, refresh_expire)
		return nil
	}

	return errcodes.SaveRefreshTokenError
}

//保存refresh token以及access_token
func (dm *DefaultDataManager) SaveAccessToken(token_data string, access_token string, access_expire time.Duration) error {
	if access_token != "" {
		//_ = dm.recycleMap.Multi()
		//defer dm.recycleMap.Exec()
		old_refresh_token := dm.recycleMap.Get(client_access_token_prefix + token_data)
		if old_refresh_token != nil {
			ttl := dm.recycleMap.TTL(old_refresh_token)
			if ttl > constants.TokenKeepExpireTime {
				dm.recycleMap.SetExpire(old_refresh_token, constants.TokenKeepExpireTime)
			}
		}
		access_token = access_token_prefix + access_token
		dm.recycleMap.Set(access_token, token_data, access_expire)
		dm.recycleMap.Set(client_access_token_prefix+token_data, access_token, access_expire)
		return nil
	}

	return errcodes.SaveAccessTokenError
}

//通过refresh token获取保存的token data
func (dm *DefaultDataManager) GetRefreshToken(refresh_token string) (string, error) {
	data := dm.recycleMap.Get(refresh_token_prefix + refresh_token)
	if data == nil {
		return "", errcodes.RefreshTokenNotFound
	} else {
		return data.(string), nil
	}
}

//通过access token获取保存的token data
func (dm *DefaultDataManager) GetAccessToken(access_token string) (string, error) {
	data := dm.recycleMap.Get(access_token_prefix + access_token)
	if data == nil {
		return "", errcodes.RefreshTokenNotFound
	} else {
		return data.(string), nil
	}
}

//废弃client_id绑定的token，包括refresh token及access token
func (dm *DefaultDataManager) RevokeToken(client_id string, token string, tokenType string) error {
	//_ = dm.recycleMap.Multi()
	//defer dm.recycleMap.Exec()
	if tokenType == constants.TokenTypeRefresh || tokenType == "" {
		refresh_token := dm.recycleMap.Get(client_refresh_token_prefix + client_id)
		if refresh_token != nil {
			dm.recycleMap.Delete(refresh_token)
			dm.recycleMap.Delete(client_refresh_token_prefix + client_id)
		}
		if tokenType == constants.TokenTypeRefresh {
			return nil
		}
	}
	if tokenType == constants.TokenTypeAccess || tokenType == "" {
		access_token := dm.recycleMap.Get(client_access_token_prefix + client_id)
		if access_token != nil {
			dm.recycleMap.Delete(access_token)
			dm.recycleMap.Delete(client_access_token_prefix + client_id)
		}
		if tokenType == constants.TokenTypeAccess {
			return nil
		}
	}

	if tokenType != "" {
		return errcodes.TokenTypeNotSupport
	} else {
		return nil
	}
}
