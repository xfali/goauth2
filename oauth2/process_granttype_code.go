/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package oauth2

import (
    "encoding/json"
    "github.com/emicklei/go-restful"
    "net/http"
    "github.com/xfali/oauth2/defines"
    "time"
)

func ProcessGrantTypeCode(auth *OAuth2, request *restful.Request, response *restful.Response) {
    //客户端标识
    client_id, err := request.BodyParameter("client_id")
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.CLINET_ID_MISSING.Error())
        return
    }

    errCode := auth.EventListener(client_id, defines.AuthorizationCodeTokenEvent)
    if errCode != nil {
        response.WriteError(errCode.HttpStatus, errCode)
    }

    //应用程序包含它在重定向中给出的授权码
    code, err := request.BodyParameter("code")
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.CODE_IS_MISSING.Error())
        return
    }

    id, err := getCode(auth.DataManager, code)
    if err != nil {
        response.WriteErrorString(http.StatusUnauthorized, defines.CODE_IS_INVALID.Error())
        return
    }

    if client_id != id {
        response.WriteErrorString(http.StatusUnauthorized, defines.CLINET_ID_NOT_MATCH.Error())
        return
    }

    //应用程序的客户端密钥。这确保了获取access token的请求只能从客户端发出，而不能从可能截获authorization code的攻击者发出
    client_secret, err := request.BodyParameter("client_secret")
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.CLIENT_SECRET_MISSING.Error())
        return
    }

    secret, err := auth.ClientManager.QuerySecret(client_id)
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.CHECK_CLIENT_ID_ERROR.Error())
        return
    }

    if client_secret != secret {
        response.WriteErrorString(http.StatusUnauthorized, defines.CLINET_SECRET_NOT_MATCH.Error())
        return
    }

    //与请求authorization code时使用的redirect_uri相同。某些资源（API）不需要此参数。
    //redirect_uri, err := request.BodyParameter("redirect_uri")
    accessToken, err := generateToken(client_id, client_secret, defines.AccessTokenExpireTime)
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.GENERATE_ACCESSTOKEN_ERROR.Error())
        return
    }

    refreshToken, err := generateToken(client_id, client_secret, defines.RefreshTokenExpireTime)
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.GENERATE_REFRESHTOKEN_ERROR.Error())
        return
    }

    token := defines.Token{
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
        TokenType:    "bearer",
        ExpiresIn:    int(defines.AccessTokenExpireTime / time.Second),
        Scope:        "",
    }

    saveToken(auth.DataManager, client_id, token.AccessToken, token.RefreshToken)

    tokenByte, err := json.Marshal(token)
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.INTERNAL_ERROR.Error())
        return
    }

    response.Write(tokenByte)

    //code只能用一次
    delCode(auth.DataManager, code)
}
