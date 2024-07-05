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
	"github.com/emicklei/go-restful"
	"github.com/xfali/oauth2/v2/constants"
	"github.com/xfali/oauth2/v2/errcodes"
	"net/http"
)

func ProcessRevokeToken(auth *OAuth2, request *restful.Request, response *restful.Response) {
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

	errCode := auth.EventListener(client_id, constants.RevokeToken)
	if errCode != nil {
		response.WriteError(errCode.HttpStatus, errCode)
		return
	}

	auth.DataManager.RevokeToken(client_id)

	response.WriteHeader(http.StatusOK)
}
