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

func ProcessGrantTypePassword(auth *OAuth2, request *restful.Request, response *restful.Response) {
	//应用程序包含它在重定向中给出的授权码
	basic := request.HeaderParameter("Authorization")

	var client_id, client_secret string

	if basic == "" {
		tmp, err := request.BodyParameter("client_id")
		if err != nil {
			response.WriteErrorString(errcodes.PasswordCredentialsHeadMissing.HttpStatus, errcodes.PasswordCredentialsHeadMissing.Error()+"and"+errcodes.ClientIdMissing.Error())
			return
		}
		client_id = tmp

		tmp2, err := request.BodyParameter("client_secret")
		if err != nil {
			response.WriteErrorString(errcodes.ClientSecretMissing.HttpStatus, errcodes.ClientSecretMissing.Error())
			return
		}
		client_secret = tmp2
	} else {
		var err *errcodes.ErrCode = nil
		client_id, client_secret, err = parseBasicInfo(basic)
		if err != nil {
			response.WriteErrorString(err.HttpStatus, err.Error())
		}
	}

	//check client_id and client_secret
	secret, err := auth.ClientManager.QuerySecret(client_id)
	if err != nil {
		response.WriteErrorString(errcodes.CheckClientIdError.HttpStatus, errcodes.CheckClientIdError.Error())
		return
	}

	if client_secret != secret {
		response.WriteErrorString(errcodes.ClientSecretNotMatch.HttpStatus, errcodes.ClientSecretNotMatch.Error())
		return
	}

	errCode := auth.EventListener(client_id, constants.PasswordTokenEvent)
	if errCode != nil {
		response.WriteError(errCode.HttpStatus, errCode)
		return
	}

	username, err := request.BodyParameter("username")
	if err != nil {
		response.WriteErrorString(errcodes.UsernameMissing.HttpStatus, errcodes.UsernameMissing.Error())
		return
	}

	password, err := request.BodyParameter("password")
	if err != nil {
		response.WriteErrorString(errcodes.PasswordMissing.HttpStatus, errcodes.PasswordMissing.Error())
		return
	}

	checkErr := auth.UserManager.CheckUser(username, password)
	if checkErr != nil {
		response.WriteErrorString(errcodes.PasswordNotMatch.HttpStatus, errcodes.PasswordNotMatch.Error())
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
		Scope:        "",
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
}
