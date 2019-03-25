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
    "github.com/xfali/goid"
    "net/http"
    "github.com/xfali/oauth2/defines"
    "github.com/xfali/oauth2/util"
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

    //scope := request.QueryParameter("scope")
    state := request.QueryParameter("state")

    code := goid.RandomId(30)
    err := saveCode(auth.DataManager, client_id, code)
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
