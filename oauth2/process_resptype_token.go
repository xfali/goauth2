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
        response.WriteErrorString(http.StatusBadRequest, defines.CLINET_ID_MISSING.Error())
        return
    }

    errCode := auth.EventListener(client_id, defines.ImplicitEvent)
    if errCode != nil {
        response.WriteError(errCode.HttpStatus, errCode)
    }

    redirect_uri := request.QueryParameter("redirect_uri")
    if redirect_uri == "" {
        response.WriteErrorString(http.StatusBadRequest, defines.REDIRECT_URI_MISSING.Error())
        return
    }
    //scope := request.QueryParameter("scope")
    state := request.QueryParameter("state")

    secret, err := auth.ClientManager.QuerySecret(client_id)
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.CHECK_CLIENT_ID_ERROR.Error())
        return
    }

    accessToken, err := generateToken(client_id, secret, defines.AccessTokenExpireTime)
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.GENERATE_ACCESSTOKEN_ERROR.Error())
        return
    }

    saveToken(auth.DataManager, client_id, accessToken, "")

    param := map[string]string{}
    param["state"] = state
    redirect_uri = util.AddParam(redirect_uri, param)
    redirect_uri = util.AddFragment(redirect_uri, "access_token", accessToken)

    http.Redirect(response.ResponseWriter, request.Request, redirect_uri, http.StatusFound)
}
