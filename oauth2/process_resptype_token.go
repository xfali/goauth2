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
	"github.com/xfali/oauth2/v2/util"
	"net/http"
)

func ProcessRespTypeToken(auth *OAuth2, request *restful.Request, response *restful.Response) {
	//FIXME:
	//redirect to user and password page

	client_id := request.QueryParameter("client_id")
	if client_id == "" {
		response.WriteErrorString(errcodes.ClientIdMissing.HttpStatus, errcodes.ClientIdMissing.Error())
		return
	}

	errCode := auth.EventListener(client_id, constants.ImplicitEvent)
	if errCode != nil {
		response.WriteError(errCode.HttpStatus, errCode)
		return
	}

	redirect_uri := request.QueryParameter("redirect_uri")
	if redirect_uri == "" {
		response.WriteErrorString(errcodes.RedirectUriMissing.HttpStatus, errcodes.RedirectUriMissing.Error())
		return
	}

	scope := request.QueryParameter("scope")
	if scope == "" {
		//response.WriteErrorString(errcodes.SCOPE_MISSING.HttpStatus, errcodes.SCOPE_MISSING.Error())
		//return
	} else {
		if !auth.ClientManager.CheckScope(client_id, RESPONSE_TYPE_TOKEN, scope) {
			response.WriteErrorString(errcodes.ScopeError.HttpStatus, errcodes.ScopeError.Error())
			return
		}
	}

	state := request.QueryParameter("state")

	secret, err := auth.ClientManager.QuerySecret(client_id)
	if err != nil {
		response.WriteErrorString(errcodes.CheckClientIdError.HttpStatus, errcodes.CheckClientIdError.Error())
		return
	}

	accessToken, err := generateToken(client_id, secret, constants.AccessTokenExpireTime)
	if err != nil {
		response.WriteErrorString(errcodes.GenerateAccessTokenError.HttpStatus, errcodes.GenerateAccessTokenError.Error())
		return
	}

	saveErr := saveToken(auth.DataManager, client_id, accessToken, "", "")
	if saveErr != nil {
		response.WriteErrorString(saveErr.HttpStatus, saveErr.Error())
		return
	}

	param := map[string]string{}
	param["state"] = state
	redirect_uri = util.AddParam(redirect_uri, param)
	redirect_uri = util.AddFragment(redirect_uri, "access_token", accessToken)

	http.Redirect(response.ResponseWriter, request.Request, redirect_uri, http.StatusFound)
}

func ProcessRespTypeWebToken(auth *OAuth2, request *restful.Request, response *restful.Response) {
	//FIXME:
	//redirect to user and password page

	client_id := request.QueryParameter("client_id")
	if client_id == "" {
		response.WriteErrorString(errcodes.ClientIdMissing.HttpStatus, errcodes.ClientIdMissing.Error())
		return
	}

	//check at begin
	//errCode := auth.EventListener(client_id, errcodes.ImplicitEvent)
	//if errCode != nil {
	//    response.WriteError(errCode.HttpStatus, errCode)
	//    return
	//}

	redirect_uri := request.QueryParameter("redirect_uri")
	if redirect_uri == "" {
		response.WriteErrorString(errcodes.RedirectUriMissing.HttpStatus, errcodes.RedirectUriMissing.Error())
		return
	}

	scope := request.QueryParameter("scope")
	if scope == "" {
		//response.WriteErrorString(errcodes.SCOPE_MISSING.HttpStatus, errcodes.SCOPE_MISSING.Error())
		//return
	} else {
		if !auth.ClientManager.CheckScope(client_id, RESPONSE_TYPE_TOKEN, scope) {
			response.WriteErrorString(errcodes.ScopeError.HttpStatus, errcodes.ScopeError.Error())
			return
		}
	}

	state := request.QueryParameter("state")

	secret, err := auth.ClientManager.QuerySecret(client_id)
	if err != nil {
		response.WriteErrorString(errcodes.CheckClientIdError.HttpStatus, errcodes.CheckClientIdError.Error())
		return
	}

	accessToken, err := generateToken(client_id, secret, constants.AccessTokenExpireTime)
	if err != nil {
		response.WriteErrorString(errcodes.GenerateAccessTokenError.HttpStatus, errcodes.GenerateAccessTokenError.Error())
		return
	}

	saveErr := saveToken(auth.DataManager, client_id, accessToken, "", "")
	if saveErr != nil {
		response.WriteErrorString(saveErr.HttpStatus, saveErr.Error())
		return
	}

	param := map[string]string{}
	param["state"] = state
	redirect_uri = util.AddParam(redirect_uri, param)
	redirect_uri = util.AddFragment(redirect_uri, "access_token", accessToken)

	http.Redirect(response.ResponseWriter, request.Request, redirect_uri, http.StatusFound)
}
