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
)

func ProcessRespTypeToken(auth *OAuth2, request *restful.Request, response *restful.Response) {
    //FIXME:
    //redirect to user and password page

    client_id := request.QueryParameter("client_id")
    if client_id == "" {
        response.WriteErrorString(defines.CLINET_ID_MISSING.HttpStatus, defines.CLINET_ID_MISSING.Error())
        return
    }

    errCode := auth.EventListener(client_id, defines.ImplicitEvent)
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
        if !auth.ClientManager.CheckScope(client_id, RESPONSE_TYPE_TOKEN, scope) {
            response.WriteErrorString(defines.SCOPE_ERROR.HttpStatus, defines.SCOPE_ERROR.Error())
            return
        }
    }

    state := request.QueryParameter("state")

    secret, err := auth.ClientManager.QuerySecret(client_id)
    if err != nil {
        response.WriteErrorString(defines.CHECK_CLIENT_ID_ERROR.HttpStatus, defines.CHECK_CLIENT_ID_ERROR.Error())
        return
    }

    accessToken, err := generateToken(client_id, secret, defines.AccessTokenExpireTime)
    if err != nil {
        response.WriteErrorString(defines.GENERATE_ACCESSTOKEN_ERROR.HttpStatus, defines.GENERATE_ACCESSTOKEN_ERROR.Error())
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
        response.WriteErrorString(defines.CLINET_ID_MISSING.HttpStatus, defines.CLINET_ID_MISSING.Error())
        return
    }

    //check at begin
    //errCode := auth.EventListener(client_id, defines.ImplicitEvent)
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
        if !auth.ClientManager.CheckScope(client_id, RESPONSE_TYPE_TOKEN, scope) {
            response.WriteErrorString(defines.SCOPE_ERROR.HttpStatus, defines.SCOPE_ERROR.Error())
            return
        }
    }

    state := request.QueryParameter("state")

    secret, err := auth.ClientManager.QuerySecret(client_id)
    if err != nil {
        response.WriteErrorString(defines.CHECK_CLIENT_ID_ERROR.HttpStatus, defines.CHECK_CLIENT_ID_ERROR.Error())
        return
    }

    accessToken, err := generateToken(client_id, secret, defines.AccessTokenExpireTime)
    if err != nil {
        response.WriteErrorString(defines.GENERATE_ACCESSTOKEN_ERROR.HttpStatus, defines.GENERATE_ACCESSTOKEN_ERROR.Error())
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