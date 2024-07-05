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

package constants

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
