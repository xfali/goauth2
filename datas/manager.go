/*
 * Copyright (C) 2024, Xiongfa Li.
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

import "time"

type DataManager interface {
	//初始化
	Init()

	//关闭
	Close()

	//保存Code相关信息，绑定client_id以及scope，在expireIn时间之后自动失效
	SaveCode(code, token string, expireIn time.Duration) error

	//通过code获得client_id以及scope
	GetCode(code string) (string, error)

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
	RevokeToken(client_id string, token string, tokenType string) error
}
