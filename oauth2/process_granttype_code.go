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
	"github.com/xfali/oauth2/v2/constants"
	"github.com/xfali/oauth2/v2/entities"
	"github.com/xfali/oauth2/v2/errcodes"
	"net/http"
	"time"
)

func ProcessGrantTypeCode(auth *OAuth2Context, request *http.Request, response http.ResponseWriter) error {
	//客户端标识
	client_id := request.FormValue("client_id")
	if client_id == "" {
		return auth.respWriter.WriteError(response, errcodes.ClientIdMissing)
	}

	errCode := auth.EventListener(client_id, constants.AuthorizationCodeTokenEvent)
	if errCode != nil {
		return auth.respWriter.WriteError(response, errCode)
	}

	//应用程序包含它在重定向中给出的授权码
	code := request.FormValue("code")
	if code == "" {
		return auth.respWriter.WriteError(response, errcodes.CodeIsMissing)
	}

	codeToken, err := auth.DataManager.GetCode(code)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.CodeIsInvalid)
	}

	//应用程序的客户端密钥。这确保了获取access token的请求只能从客户端发出，而不能从可能截获authorization code的攻击者发出
	client_secret := request.FormValue("client_secret")
	if client_secret == "" {
		return auth.respWriter.WriteError(response, errcodes.ClientSecretMissing)
	}

	secret, err := auth.ClientManager.QuerySecret(client_id)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.CheckClientIdError)
	}

	if client_secret != secret {
		return auth.respWriter.WriteError(response, errcodes.ClientSecretNotMatch)
	}

	claims, err := parseTokenClaims(client_secret, codeToken)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.CodeIsInvalid)
	}
	if id, ok := claims[TokenClaimKeyClientId]; ok {
		if client_id != id.(string) {
			return auth.respWriter.WriteError(response, errcodes.ClientSecretNotMatch)
		}
	} else {
		return auth.respWriter.WriteError(response, errcodes.CodeIsInvalid)
	}

	//与请求authorization code时使用的redirect_uri相同。某些资源（API）不需要此参数。
	//redirect_uri, err := request.BodyParameter("redirect_uri")
	accessToken, err := generateToken(client_id, client_secret, constants.AccessTokenExpireTime)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.GenerateAccessTokenError)
	}

	refreshToken, err := generateToken(client_id, client_secret, constants.RefreshTokenExpireTime)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.GenerateRefreshTokenError)
	}

	scope := ""
	if v, ok := claims["scope"]; ok {
		scope = v.(string)
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
		return auth.respWriter.WriteError(response, saveErr)
	}

	tokenByte, err := json.Marshal(&token)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.InternalError)
	}
	//code只能用一次
	defer auth.DataManager.DelCode(code)

	return auth.respWriter.Write(response, string(tokenByte))

}
