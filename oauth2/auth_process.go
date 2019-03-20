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
    "github.com/xfali/goid"
    "oauth2/util"
    "oauth2/defines"
    "encoding/json"
)

func ProcessRespCodeType(auth *OAuth2, request *restful.Request, response *restful.Response) {
    client_id := request.QueryParameter("client_id")
    redirect_uri := request.QueryParameter("redirect_uri")
    //scope := request.QueryParameter("scope")
    state := request.QueryParameter("state")

    code := goid.RandomId(30)
    auth.DataManager.Set(code, client_id, auth.CodeExpireTime)
    param := map[string] string{}
    param["code"] = code
    param["state"] = state
    redirect_uri = util.AddParam(redirect_uri, param)
    http.Redirect(response.ResponseWriter, request.Request, redirect_uri, http.StatusFound)
}

func ProcessRespTokenType(auth *OAuth2, request *restful.Request, response *restful.Response) {

}

func ProcessGrantCodeType(auth *OAuth2, request *restful.Request, response *restful.Response) {
    //应用程序包含它在重定向中给出的授权码
    code, err := request.BodyParameter("code")
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.CODE_IS_MISSING.Error())
        return
    }

    id, err := auth.DataManager.Get(code)
    if err != nil {
        response.WriteErrorString(http.StatusUnauthorized, defines.CODE_IS_INVALID.Error())
        return
    }

    //客户端标识
    client_id, err := request.BodyParameter("client_id")
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.CLINET_ID_MISSING.Error())
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
    token := defines.Token{
        AccessToken: generateToken(client_id),
        RefreshToken: generateToken(client_id),
        TokenType: "bearer",
        ExpiresIn: 3600,
        Scope: "",
    }

    tokenByte, err := json.Marshal(token)
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.INTERNAL_ERROR.Error())
        return
    }

    response.Write(tokenByte)

    //code只能用一次
    auth.DataManager.Del(code)
}
