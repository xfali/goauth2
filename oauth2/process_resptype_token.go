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
	"github.com/xfali/oauth2/v2/util"
	"net/http"
)

func ProcessRespTypeToken(auth *OAuth2Context, request *http.Request, response http.ResponseWriter) error {
	//FIXME:
	//redirect to user and password page
	query := request.URL.Query()
	client_id := query.Get("client_id")
	if client_id == "" {
		return auth.respWriter.WriteError(response, errcodes.ClientIdMissing)
	}

	errCode := auth.EventListener(client_id, constants.ImplicitEvent)
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
		if !auth.ClientManager.CheckScope(client_id, ResponseTypeToken, scope) {
			return auth.respWriter.WriteError(response, errcodes.ScopeError)
		}
	}

	state := query.Get("state")

	secret, err := auth.ClientManager.QuerySecret(client_id)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.CheckClientIdError)
	}

	accessToken, err := generateToken(client_id, secret, constants.AccessTokenExpireTime)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.GenerateAccessTokenError)
	}

	saveErr := saveToken(auth.DataManager, client_id, accessToken, "", "")
	if saveErr != nil {
		return auth.respWriter.WriteError(response, saveErr)
	}

	param := map[string]string{}
	param["state"] = state
	redirect_uri = util.AddParam(redirect_uri, param)
	redirect_uri = util.AddFragment(redirect_uri, "access_token", accessToken)

	http.Redirect(response, request, redirect_uri, http.StatusFound)
	return nil
}

func ProcessRespTypeWebToken(auth *OAuth2Context, request *http.Request, response http.ResponseWriter) error {
	//FIXME:
	//redirect to user and password page

	query := request.URL.Query()
	client_id := query.Get("client_id")
	if client_id == "" {
		return auth.respWriter.WriteError(response, errcodes.ClientIdMissing)
	}

	//check at begin
	//errCode := auth.EventListener(client_id, errcodes.ImplicitEvent)
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
		if !auth.ClientManager.CheckScope(client_id, ResponseTypeToken, scope) {
			return auth.respWriter.WriteError(response, errcodes.ScopeError)
		}
	}

	state := query.Get("state")

	secret, err := auth.ClientManager.QuerySecret(client_id)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.CheckClientIdError)
	}

	accessToken, err := generateToken(client_id, secret, constants.AccessTokenExpireTime)
	if err != nil {
		return auth.respWriter.WriteError(response, errcodes.GenerateAccessTokenError)
	}

	saveErr := saveToken(auth.DataManager, client_id, accessToken, "", "")
	if saveErr != nil {
		return auth.respWriter.WriteError(response, saveErr)
	}

	param := map[string]string{}
	param["state"] = state
	redirect_uri = util.AddParam(redirect_uri, param)
	redirect_uri = util.AddFragment(redirect_uri, "access_token", accessToken)

	http.Redirect(response, request, redirect_uri, http.StatusFound)
	return nil
}
