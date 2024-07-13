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
	"github.com/xfali/oauth2/v2/configs"
	"github.com/xfali/oauth2/v2/constants"
	"github.com/xfali/oauth2/v2/entities"
	"github.com/xfali/oauth2/v2/errcodes"
	"net/http"
	"time"
)

// ProcessGrantTypeRefreshToken
// [OAuth 2.0 Password Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.3)
/*
	POST /token HTTP/1.1
	Host: server.example.com
	Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
	Content-Type: application/x-www-form-urlencoded

	grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
*/
func ProcessGrantTypeRefreshToken(auth *OAuth2Context, request *http.Request, response http.ResponseWriter) error {
	//应用程序包含它在重定向中给出的授权码
	basic := request.Header.Get(configs.OAuth2BasicAuthorizationKey)

	var client_id, client_secret string
	if basic == "" {
		client_id = request.FormValue("client_id")
		if client_id == "" {
			return auth.respWriter.WriteError(response, errcodes.ClientIdMissing)
		}

		client_secret = request.FormValue("client_secret")
		if client_secret == "" {
			return auth.respWriter.WriteError(response, errcodes.ClientSecretMissing)
		}
	} else {
		var err *errcodes.ErrCode = nil
		client_id, client_secret, err = parseBasicInfo(basic)
		if err != nil {
			return auth.respWriter.WriteError(response, err)
		}
	}

	//check client_id and client_secret
	secret, err := auth.ClientManager.QuerySecret(client_id)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.CheckClientIdError)
	}

	if client_secret != secret {
		return auth.respWriter.WriteError(response, errcodes.ClientSecretNotMatch)
	}

	errCode := auth.EventListener(client_id, constants.RequestRefreshTokenEvent)
	if errCode != nil {
		return auth.respWriter.WriteError(response, errCode)
	}

	refresh_token := request.FormValue("refresh_token")
	if refresh_token == "" {
		return auth.respWriter.WriteError(response, errcodes.RefreshTokenMissing)
	}

	jwt_client_id, err := parseToken(secret, refresh_token)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.TokenError)
	}

	if client_id != jwt_client_id {
		return auth.respWriter.WriteError(response, errcodes.CheckClientIdError)
	}

	token_data, err := auth.DataManager.GetRefreshToken(refresh_token)
	if err != nil || token_data == "" {
		return auth.respWriter.WriteError(response, errcodes.RefreshTokenNotFound)
	}

	//FIXME 不需要比较缓存中的数据？
	//if client_id != token_data {
	//    response.WriteErrorString(errcodes.CHECK_CLIENT_ID_ERROR.HttpStatus, errcodes.CHECK_CLIENT_ID_ERROR.Error())
	//    return
	//}

	//与请求authorization code时使用的redirect_uri相同。某些资源（API）不需要此参数。
	//redirect_uri, err := request.BodyParameter("redirect_uri")
	accessToken, err := generateToken(client_id, client_secret, constants.AccessTokenExpireTime)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.GenerateAccessTokenError)
	}

	token := entities.Token{
		AccessToken: accessToken,
		TokenType:   "bearer",
		ExpiresIn:   int(constants.AccessTokenExpireTime / time.Second),
		Scope:       "",
	}

	saveErr := saveToken(auth.DataManager, client_id, token.AccessToken, client_id, token.RefreshToken)
	if saveErr != nil {
		return auth.respWriter.WriteError(response, saveErr)
	}

	tokenByte, err := json.Marshal(&token)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.InternalError)
	}

	return auth.respWriter.Write(response, string(tokenByte))
}
