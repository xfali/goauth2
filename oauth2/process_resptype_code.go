/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package oauth2

import (
    "github.com/emicklei/go-restful"
    "net/http"
    "github.com/xfali/oauth2/defines"
    "github.com/xfali/oauth2/util"
    "github.com/xfali/goutils/idUtil"
)

func ProcessRespTypeCode(auth *OAuth2, request *restful.Request, response *restful.Response) {
    //FIXME:
    //redirect to user and password page

    client_id := request.QueryParameter("client_id")
    if client_id == "" {
        response.WriteErrorString(defines.CLINET_ID_MISSING.HttpStatus, defines.CLINET_ID_MISSING.Error())
        return
    }

    errCode := auth.EventListener(client_id, defines.AuthorizationCodeEvent)
    if errCode != nil {
        response.WriteError(errCode.HttpStatus, errCode)
        return
    }

    redirect_uri := request.QueryParameter("redirect_uri")
    if redirect_uri == "" {
        response.WriteErrorString(defines.REDIRECT_URI_MISSING.HttpStatus, defines.REDIRECT_URI_MISSING.Error())
        return
    }

    scope := request.QueryParameter("scope")
    if scope == "" {
        //response.WriteErrorString(defines.SCOPE_MISSING.HttpStatus, defines.SCOPE_MISSING.Error())
        //return
    } else {
        if !auth.ClientManager.CheckScope(client_id, RESPONSE_TYPE_CODE, scope) {
            response.WriteErrorString(defines.SCOPE_ERROR.HttpStatus, defines.SCOPE_ERROR.Error())
            return
        }
    }

    url, err := auth.UserManager.UserAuthorize(request.Request)
    if err != nil {
        response.WriteErrorString(defines.USERAUTHORIZE_CHECK_ERROR.HttpStatus, defines.USERAUTHORIZE_CHECK_ERROR.Error())
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
        response.WriteErrorString(defines.CLINET_ID_MISSING.HttpStatus, defines.CLINET_ID_MISSING.Error())
        return
    }

    //check at begin
    //errCode := auth.EventListener(client_id, defines.AuthorizationCodeEvent)
    //if errCode != nil {
    //    response.WriteError(errCode.HttpStatus, errCode)
    //    return
    //}

    redirect_uri := request.QueryParameter("redirect_uri")
    if redirect_uri == "" {
        response.WriteErrorString(defines.REDIRECT_URI_MISSING.HttpStatus, defines.REDIRECT_URI_MISSING.Error())
        return
    }

    scope := request.QueryParameter("scope")
    if scope == "" {
        //response.WriteErrorString(defines.SCOPE_MISSING.HttpStatus, defines.SCOPE_MISSING.Error())
        //return
    } else {
        if !auth.ClientManager.CheckScope(client_id, RESPONSE_TYPE_CODE, scope) {
            response.WriteErrorString(defines.SCOPE_ERROR.HttpStatus, defines.SCOPE_ERROR.Error())
            return
        }
    }

    state := request.QueryParameter("state")

    code := idUtil.RandomId(30)
    err := auth.DataManager.SaveCode(client_id, code, scope, auth.CodeExpireTime)
    if err != nil {
        response.WriteErrorString(defines.SAVE_DATA_ERROR.HttpStatus, defines.SAVE_DATA_ERROR.Error())
        return
    }

    param := map[string]string{}
    param["code"] = code
    param["state"] = state
    redirect_uri = util.AddParam(redirect_uri, param)
    http.Redirect(response.ResponseWriter, request.Request, redirect_uri, http.StatusFound)
}
