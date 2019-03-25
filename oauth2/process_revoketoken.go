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
)

func ProcessRevokeToken(auth *OAuth2, request *restful.Request, response *restful.Response) {
    //应用程序包含它在重定向中给出的授权码
    basic := request.HeaderParameter("Authorization")

    var client_id, client_secret string
    if basic == "" {
        tmp, err := request.BodyParameter("client_id")
        if err != nil {
            response.WriteErrorString(defines.PASSWORD_CREDENTIALS_HEAD_MISSING.HttpStatus, defines.PASSWORD_CREDENTIALS_HEAD_MISSING.Error()+"and"+defines.CLINET_ID_MISSING.Error())
            return
        }
        client_id = tmp

        tmp2, err := request.BodyParameter("client_secret")
        if err != nil {
            response.WriteErrorString(defines.CLIENT_SECRET_MISSING.HttpStatus, defines.CLIENT_SECRET_MISSING.Error())
            return
        }
        client_secret = tmp2
    } else {
        var err *defines.ErrCode = nil
        client_id, client_secret, err = parseBasicInfo(basic)
        if err != nil {
            response.WriteErrorString(err.HttpStatus, err.Error())
        }
    }

    //check client_id and client_secret
    secret, err := auth.ClientManager.QuerySecret(client_id)
    if err != nil {
        response.WriteErrorString(defines.CHECK_CLIENT_ID_ERROR.HttpStatus, defines.CHECK_CLIENT_ID_ERROR.Error())
        return
    }

    if client_secret != secret {
        response.WriteErrorString(defines.CLINET_SECRET_NOT_MATCH.HttpStatus, defines.CLINET_SECRET_NOT_MATCH.Error())
        return
    }

    errCode := auth.EventListener(client_id, defines.RevokeToken)
    if errCode != nil {
        response.WriteError(errCode.HttpStatus, errCode)
        return
    }

    auth.DataManager.RevokeToken(client_id)

    response.WriteHeader(http.StatusOK)
}
