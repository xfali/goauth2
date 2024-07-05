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

package oauth2

import (
	"encoding/json"
	"github.com/emicklei/go-restful"
	"github.com/xfali/oauth2/v2/constants"
	"github.com/xfali/oauth2/v2/entities"
	"github.com/xfali/oauth2/v2/errcodes"
	"time"
)

func ProcessGrantTypeCode(auth *OAuth2, request *restful.Request, response *restful.Response) {
	//客户端标识
	client_id, err := request.BodyParameter("client_id")
	if err != nil {
		response.WriteErrorString(errcodes.ClientIdMissing.HttpStatus, errcodes.ClientIdMissing.Error())
		return
	}

	errCode := auth.EventListener(client_id, constants.AuthorizationCodeTokenEvent)
	if errCode != nil {
		response.WriteError(errCode.HttpStatus, errCode)
		return
	}

	//应用程序包含它在重定向中给出的授权码
	code, err := request.BodyParameter("code")
	if err != nil {
		response.WriteErrorString(errcodes.CodeIsMissing.HttpStatus, errcodes.CodeIsMissing.Error())
		return
	}

	id, scope, err := auth.DataManager.GetCode(code)
	if err != nil {
		response.WriteErrorString(errcodes.CodeIsInvalid.HttpStatus, errcodes.CodeIsInvalid.Error())
		return
	}

	if client_id != id {
		response.WriteErrorString(errcodes.ClientSecretNotMatch.HttpStatus, errcodes.ClientSecretNotMatch.Error())
		return
	}

	//应用程序的客户端密钥。这确保了获取access token的请求只能从客户端发出，而不能从可能截获authorization code的攻击者发出
	client_secret, err := request.BodyParameter("client_secret")
	if err != nil {
		response.WriteErrorString(errcodes.ClientSecretMissing.HttpStatus, errcodes.ClientSecretMissing.Error())
		return
	}

	secret, err := auth.ClientManager.QuerySecret(client_id)
	if err != nil {
		response.WriteErrorString(errcodes.CheckClientIdError.HttpStatus, errcodes.CheckClientIdError.Error())
		return
	}

	if client_secret != secret {
		response.WriteErrorString(errcodes.ClientSecretNotMatch.HttpStatus, errcodes.ClientSecretNotMatch.Error())
		return
	}

	//与请求authorization code时使用的redirect_uri相同。某些资源（API）不需要此参数。
	//redirect_uri, err := request.BodyParameter("redirect_uri")
	accessToken, err := generateToken(client_id, client_secret, constants.AccessTokenExpireTime)
	if err != nil {
		response.WriteErrorString(errcodes.GenerateAccessTokenError.HttpStatus, errcodes.GenerateAccessTokenError.Error())
		return
	}

	refreshToken, err := generateToken(client_id, client_secret, constants.RefreshTokenExpireTime)
	if err != nil {
		response.WriteErrorString(errcodes.GenerateRefreshTokenError.HttpStatus, errcodes.GenerateRefreshTokenError.Error())
		return
	}

	token := entities.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "bearer",
		ExpiresIn:    int(constants.AccessTokenExpireTime / time.Second),
		Scope:        scope,
	}

	saveErr := saveToken(auth.DataManager, client_id, token.AccessToken, client_id, token.RefreshToken)
	if saveErr != nil {
		response.WriteErrorString(saveErr.HttpStatus, saveErr.Error())
		return
	}

	tokenByte, err := json.Marshal(&token)
	if err != nil {
		response.WriteErrorString(errcodes.InternalError.HttpStatus, errcodes.InternalError.Error())
		return
	}

	response.Write(tokenByte)

	//code只能用一次
	auth.DataManager.DelCode(code)
}
