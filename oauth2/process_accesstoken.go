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
    "io"
    "github.com/xfali/oauth2/defines"
)

func ProcessAccessToken(auth *OAuth2, request *restful.Request, response *restful.Response) {
    authorization := request.HeaderParameter("Authorization")

    if authorization == "" {
        response.WriteErrorString(defines.ACCESSTOKEN_MISSING.HttpStatus, defines.ACCESSTOKEN_MISSING.Error())
        return
    }

    access_token, _ := parseBearerInfo(authorization)

    client_id, err := auth.DataManager.GetAccessToken(access_token)
    if err != nil || client_id == "" {
        response.WriteErrorString(defines.AUTHENTICATE_ACCESSTOKEN_ERROR.HttpStatus, defines.AUTHENTICATE_ACCESSTOKEN_ERROR.Error())
        return
    }

    errCode := auth.EventListener(client_id, defines.AuthenticateToken)
    if errCode != nil {
        response.WriteError(errCode.HttpStatus, errCode)
        return
    }

    io.WriteString(response.ResponseWriter, client_id)
}
