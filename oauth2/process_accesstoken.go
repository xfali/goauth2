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
    "net/http"
    "oauth2/defines"
)

func ProcessAccessToken(auth *OAuth2, request *restful.Request, response *restful.Response) {
    authorization := request.HeaderParameter("Authorization")

    if authorization == "" {
        response.WriteErrorString(http.StatusUnauthorized, defines.ACCESSTOKEN_MISSING.Error())
        return
    }

    access_token, _ := parseBearerInfo(authorization)

    client_id, err := getAccessToken(auth.DataManager, access_token)
    if err != nil {
        response.WriteErrorString(http.StatusUnauthorized, defines.AUTHENTICATE_ACCESSTOKEN_ERROR.Error())
        return
    }

    io.WriteString(response.ResponseWriter, client_id)
}
