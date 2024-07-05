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
	"io"
)

func ProcessAccessToken(auth *OAuth2, request *restful.Request, response *restful.Response) {
	authorization := request.HeaderParameter("Authorization")

	if authorization == "" {
		response.WriteErrorString(errcodes.AccessTokenMissing.HttpStatus, errcodes.AccessTokenMissing.Error())
		return
	}

	access_token, _ := parseBearerInfo(authorization)

	client_id, err := auth.DataManager.GetAccessToken(access_token)
	if err != nil || client_id == "" {
		response.WriteErrorString(errcodes.AuthenticateAccessTokenError.HttpStatus, errcodes.AuthenticateAccessTokenError.Error())
		return
	}

	errCode := auth.EventListener(client_id, constants.AuthenticateToken)
	if errCode != nil {
		response.WriteError(errCode.HttpStatus, errCode)
		return
	}

	io.WriteString(response.ResponseWriter, client_id)
}
