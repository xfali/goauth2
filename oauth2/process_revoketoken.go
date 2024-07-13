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
	"github.com/xfali/oauth2/v2/configs"
	"github.com/xfali/oauth2/v2/constants"
	"github.com/xfali/oauth2/v2/errcodes"
	"net/http"
)

// ProcessRevokeToken
// [RFC 7009: Token Revocation](tools.ietf.org/html/rfc7009)
func ProcessRevokeToken(auth *OAuth2Context, request *http.Request, response http.ResponseWriter) error {
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

	token := request.FormValue("token")
	tokenType := request.FormValue("token_type_hint")

	errCode := auth.EventListener(client_id, constants.RevokeToken)
	if errCode != nil {
		return auth.respWriter.WriteError(response, errCode)
	}

	err = auth.DataManager.RevokeToken(client_id, token, tokenType)
	if err != nil {
		if errC, ok := err.(*errcodes.ErrCode); ok {
			return auth.respWriter.WriteError(response, errC)
		} else {
			auth.logger.Errorln(err)
			return auth.respWriter.WriteError(response, errcodes.RevokeTokenError)
		}
	} else {
		_ = auth.respWriter.Write(response, nil)
	}

	return nil
}
