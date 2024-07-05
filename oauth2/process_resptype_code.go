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
	"github.com/xfali/goutils/idUtil"
	"github.com/xfali/oauth2/v2/constants"
	"github.com/xfali/oauth2/v2/errcodes"
	"github.com/xfali/oauth2/v2/util"
	"net/http"
)

func ProcessRespTypeCode(auth *OAuth2, request *restful.Request, response *restful.Response) {
	//FIXME:
	//redirect to user and password page

	client_id := request.QueryParameter("client_id")
	if client_id == "" {
		response.WriteErrorString(errcodes.ClientIdMissing.HttpStatus, errcodes.ClientIdMissing.Error())
		return
	}

	errCode := auth.EventListener(client_id, constants.AuthorizationCodeEvent)
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
		if !auth.ClientManager.CheckScope(client_id, RESPONSE_TYPE_CODE, scope) {
			response.WriteErrorString(errcodes.ScopeError.HttpStatus, errcodes.ScopeError.Error())
			return
		}
	}

	url, err := auth.UserManager.UserAuthorize(request.Request)
	if err != nil {
		response.WriteErrorString(errcodes.UserAuthorizeCheckError.HttpStatus, errcodes.UserAuthorizeCheckError.Error())
		return
	}

	state := request.QueryParameter("state")

	param := map[string]string{}
	param["client_id"] = client_id
	param["redirect_uri"] = redirect_uri
	param["state"] = state
	param["scope"] = scope
	param["response_type"] = RESPONSE_TYPE_CODE
	param["callback"] = auth.Addr + "/oauth2/authorize/web"

	url = util.AddParam(url, param)

	http.Redirect(response.ResponseWriter, request.Request, url, http.StatusFound)
}

func ProcessRespTypeWebCode(auth *OAuth2, request *restful.Request, response *restful.Response) {
	//FIXME:
	//redirect to user and password page

	client_id := request.QueryParameter("client_id")
	if client_id == "" {
		response.WriteErrorString(errcodes.ClientIdMissing.HttpStatus, errcodes.ClientIdMissing.Error())
		return
	}

	//check at begin
	//errCode := auth.EventListener(client_id, errcodes.AuthorizationCodeEvent)
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
		if !auth.ClientManager.CheckScope(client_id, RESPONSE_TYPE_CODE, scope) {
			response.WriteErrorString(errcodes.ScopeError.HttpStatus, errcodes.ScopeError.Error())
			return
		}
	}

	state := request.QueryParameter("state")

	code := idUtil.RandomId(30)
	err := auth.DataManager.SaveCode(client_id, code, scope, auth.CodeExpireTime)
	if err != nil {
		response.WriteErrorString(errcodes.SaveDataError.HttpStatus, errcodes.SaveDataError.Error())
		return
	}

	param := map[string]string{}
	param["code"] = code
	param["state"] = state
	redirect_uri = util.AddParam(redirect_uri, param)
	http.Redirect(response.ResponseWriter, request.Request, redirect_uri, http.StatusFound)
}
