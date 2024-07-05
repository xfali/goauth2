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
	"github.com/xfali/oauth2/v2/constants"
	"github.com/xfali/oauth2/v2/errcodes"
	"net/http"
)

func ProcessAccessToken(auth *OAuth2Context, request *http.Request, response http.ResponseWriter) error {
	authorization := request.Header.Get("Authorization")

	if authorization == "" {
		return auth.respWriter.WriteError(response, errcodes.AccessTokenMissing)
	}

	access_token, _ := parseBearerInfo(authorization)

	client_id, err := auth.DataManager.GetAccessToken(access_token)
	if err != nil || client_id == "" {
		return auth.respWriter.WriteError(response, errcodes.AuthenticateAccessTokenError)
	}

	errCode := auth.EventListener(client_id, constants.AuthenticateToken)
	if errCode != nil {
		return auth.respWriter.WriteError(response, errCode)
	}

	return auth.respWriter.Write(response, client_id)
}
