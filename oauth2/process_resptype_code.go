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
	"github.com/xfali/goutils/idUtil"
	"github.com/xfali/oauth2/v2/constants"
	"github.com/xfali/oauth2/v2/errcodes"
	"github.com/xfali/oauth2/v2/util"
	"net/http"
)

func ProcessRespTypeCode(auth *OAuth2Context, request *http.Request, response http.ResponseWriter) error {
	//FIXME:
	//redirect to user and password page

	query := request.URL.Query()
	client_id := query.Get("client_id")
	if client_id == "" {
		return auth.respWriter.WriteError(response, errcodes.ClientIdMissing)
	}

	errCode := auth.EventListener(client_id, constants.AuthorizationCodeEvent)
	if errCode != nil {
		return auth.respWriter.WriteError(response, errCode)
	}

	redirect_uri := query.Get("redirect_uri")
	if redirect_uri == "" {
		return auth.respWriter.WriteError(response, errcodes.RedirectUriMissing)
	}

	scope := query.Get("scope")
	if scope == "" {
		//response.WriteErrorString(errcodes.SCOPE_MISSING.HttpStatus, errcodes.SCOPE_MISSING.Error())
		//return
	} else {
		if !auth.ClientManager.CheckScope(client_id, ResponseTypeCode, scope) {
			return auth.respWriter.WriteError(response, errcodes.ScopeError)
		}
	}

	url, err := auth.UserManager.UserAuthorize(request)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.UserAuthorizeCheckError)
	}

	state := query.Get("state")

	param := map[string]string{}
	param["client_id"] = client_id
	param["redirect_uri"] = redirect_uri
	param["state"] = state
	param["scope"] = scope
	param["response_type"] = ResponseTypeCode
	param["callback"] = auth.CallbackUrl

	url = util.AddParam(url, param)

	http.Redirect(response, request, url, http.StatusFound)
	return nil
}

func ProcessRespTypeWebCode(auth *OAuth2Context, request *http.Request, response http.ResponseWriter) error {
	userToken, err := auth.UserManager.ExtractToken(request)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.AccessTokenMissing)
	}

	token_client_id, err := auth.DataManager.GetAccessToken(userToken)
	if err != nil || token_client_id == "" {
		return auth.respWriter.WriteError(response, errcodes.AuthenticateAccessTokenError)
	}

	query := request.URL.Query()
	client_id := query.Get("client_id")
	if client_id == "" {
		return auth.respWriter.WriteError(response, errcodes.ClientIdMissing)
	}

	if token_client_id != client_id {
		return auth.respWriter.WriteError(response, errcodes.ClientIdNotMatch)
	}

	client_secret, err := auth.ClientManager.QuerySecret(client_id)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.CheckClientIdError)
	}

	claims, err := parseTokenClaims(client_secret, userToken)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.AuthenticateAccessTokenError)
	}

	var username string
	if v, ok := claims[TokenClaimKeyUsername]; ok {
		username = v.(string)
	} else {
		return auth.respWriter.WriteError(response, errcodes.AuthenticateAccessTokenError)
	}

	//check at begin
	//errCode := auth.EventListener(client_id, errcodes.AuthorizationCodeEvent)
	//if errCode != nil {
	//    response.WriteError(errCode.HttpStatus, errCode)
	//    return
	//}

	redirect_uri := query.Get("redirect_uri")
	if redirect_uri == "" {
		return auth.respWriter.WriteError(response, errcodes.RedirectUriMissing)
	}

	scope := query.Get("scope")
	if scope == "" {
		//response.WriteErrorString(errcodes.SCOPE_MISSING.HttpStatus, errcodes.SCOPE_MISSING.Error())
		//return
	} else {
		if !auth.ClientManager.CheckScope(client_id, ResponseTypeCode, scope) {
			return auth.respWriter.WriteError(response, errcodes.ScopeError)
		}
	}

	state := query.Get("state")

	code := idUtil.RandomId(30)
	token, err := generateToken(client_id, client_secret, auth.CodeExpireTime, map[string]string{
		TokenClaimKeyScope:    scope,
		TokenClaimKeyUsername: username,
	})
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.SaveDataError)
	}

	err = auth.DataManager.SaveCode(code, token, auth.CodeExpireTime)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.SaveDataError)
	}

	param := map[string]string{}
	param["code"] = code
	param["state"] = state
	redirect_uri = util.AddParam(redirect_uri, param)
	http.Redirect(response, request, redirect_uri, http.StatusFound)
	return nil
}
