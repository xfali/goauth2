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
    "strings"
    "encoding/base64"
)

const(
    access_token_prefix = "access_token:"
    refresh_token_prefix = "refresh_token:"
)

func ProcessRespCodeType(auth *OAuth2, request *restful.Request, response *restful.Response) {
    //FIXME:
    //redirect to user and password page

    client_id := request.QueryParameter("client_id")
    if client_id == "" {
        response.WriteErrorString(http.StatusBadRequest, defines.CLINET_ID_MISSING.Error())
        return
    }

    errCode := auth.EventListener(client_id, defines.AuthorizationCodeEvent)
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

    code := goid.RandomId(30)
    auth.DataManager.Set(code, client_id, auth.CodeExpireTime)
    param := map[string] string{}
    param["code"] = code
    param["state"] = state
    redirect_uri = util.AddParam(redirect_uri, param)
    http.Redirect(response.ResponseWriter, request.Request, redirect_uri, http.StatusFound)
}

func ProcessRespTokenType(auth *OAuth2, request *restful.Request, response *restful.Response) {
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

    param := map[string] string{}
    param["state"] = state
    redirect_uri = util.AddParam(redirect_uri, param)
    redirect_uri = util.AddFragment(redirect_uri, "access_token", accessToken)

    http.Redirect(response.ResponseWriter, request.Request, redirect_uri, http.StatusFound)
}

func ProcessGrantCodeType(auth *OAuth2, request *restful.Request, response *restful.Response) {
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

    id, err := auth.DataManager.Get(code)
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
        AccessToken: accessToken,
        RefreshToken: refreshToken,
        TokenType: "bearer",
        ExpiresIn: int(defines.AccessTokenExpireTime),
        Scope: "",
    }

    saveToken(auth.DataManager, client_id, token.AccessToken, token.RefreshToken)

    tokenByte, err := json.Marshal(token)
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.INTERNAL_ERROR.Error())
        return
    }

    response.Write(tokenByte)

    //code只能用一次
    auth.DataManager.Del(code)
}

func ProcessGrantPasswordType(auth *OAuth2, request *restful.Request, response *restful.Response) {
    //应用程序包含它在重定向中给出的授权码
    basic := request.HeaderParameter("Authorization")
    //if basic =="" {
    //    response.WriteErrorString(http.StatusBadRequest, )
    //    return
    //}

    var client_id, client_secret string

    if basic == "" {
        tmp, err := request.BodyParameter("client_id")
        if err != nil {
            response.WriteErrorString(http.StatusBadRequest, defines.PASSWORD_CREDENTIALS_HEAD_MISSING.Error() + "and" + defines.CLINET_ID_MISSING.Error())
            return
        }
        client_id = tmp

        tmp2, err := request.BodyParameter("client_secret")
        if err != nil {
            response.WriteErrorString(http.StatusBadRequest, defines.CLIENT_SECRET_MISSING.Error())
            return
        }
        client_secret = tmp2
    } else {
        var err error = nil
        client_id, client_secret, err = parseBasicInfo(basic)
        if err != nil {
            response.WriteErrorString(http.StatusBadRequest, err.Error())
        }
    }

    //check client_id and client_secret
    secret, err := auth.ClientManager.QuerySecret(client_id)
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.CHECK_CLIENT_ID_ERROR.Error())
        return
    }

    if client_secret != secret {
        response.WriteErrorString(http.StatusUnauthorized, defines.CLINET_SECRET_NOT_MATCH.Error())
        return
    }

    errCode := auth.EventListener(client_id, defines.PasswordTokenEvent)
    if errCode != nil {
        response.WriteError(errCode.HttpStatus, errCode)
    }

    username, err := request.BodyParameter("username")
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.USERNAME_MISSING.Error())
        return
    }

    password, err := request.BodyParameter("password")
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.PASSWORD_MISSING.Error())
        return
    }

    checkErr := auth.UserManager.CheckUser(username, password)
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, checkErr.Error())
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
        AccessToken: accessToken,
        RefreshToken: refreshToken,
        TokenType: "bearer",
        ExpiresIn: int(defines.AccessTokenExpireTime),
        Scope: "",
    }

    saveToken(auth.DataManager, client_id, token.AccessToken, token.RefreshToken)

    tokenByte, err := json.Marshal(token)
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.INTERNAL_ERROR.Error())
        return
    }

    response.Write(tokenByte)
}

func ProcessGrantClientCredentialsType(auth *OAuth2, request *restful.Request, response *restful.Response) {
    //应用程序包含它在重定向中给出的授权码
    basic := request.HeaderParameter("Authorization")
    //if basic =="" {
    //    response.WriteErrorString(http.StatusBadRequest, )
    //    return
    //}

    var client_id, client_secret string
    if basic == "" {
        tmp, err := request.BodyParameter("client_id")
        if err != nil {
            response.WriteErrorString(http.StatusBadRequest, defines.PASSWORD_CREDENTIALS_HEAD_MISSING.Error() + "and" + defines.CLINET_ID_MISSING.Error())
            return
        }
        client_id = tmp

        tmp2, err := request.BodyParameter("client_secret")
        if err != nil {
            response.WriteErrorString(http.StatusBadRequest, defines.CLIENT_SECRET_MISSING.Error())
            return
        }
        client_secret = tmp2
    } else {
        var err error = nil
        client_id, client_secret, err = parseBasicInfo(basic)
        if err != nil {
            response.WriteErrorString(http.StatusBadRequest, err.Error())
        }
    }

    //check client_id and client_secret
    secret, err := auth.ClientManager.QuerySecret(client_id)
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.CHECK_CLIENT_ID_ERROR.Error())
        return
    }

    if client_secret != secret {
        response.WriteErrorString(http.StatusUnauthorized, defines.CLINET_SECRET_NOT_MATCH.Error())
        return
    }

    errCode := auth.EventListener(client_id, defines.ClientCredentialsTokenEvent)
    if errCode != nil {
        response.WriteError(errCode.HttpStatus, errCode)
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
        AccessToken: accessToken,
        RefreshToken: refreshToken,
        TokenType: "bearer",
        ExpiresIn: int(defines.AccessTokenExpireTime),
        Scope: "",
    }

    saveToken(auth.DataManager, client_id, token.AccessToken, token.RefreshToken)

    tokenByte, err := json.Marshal(token)
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.INTERNAL_ERROR.Error())
        return
    }

    response.Write(tokenByte)
}

func ProcessGrantRefreshTokenType(auth *OAuth2, request *restful.Request, response *restful.Response) {
    //应用程序包含它在重定向中给出的授权码
    basic := request.HeaderParameter("Authorization")
    //if basic =="" {
    //    response.WriteErrorString(http.StatusBadRequest, )
    //    return
    //}

    var client_id, client_secret string
    if basic == "" {
        tmp, err := request.BodyParameter("client_id")
        if err != nil {
            response.WriteErrorString(http.StatusBadRequest, defines.PASSWORD_CREDENTIALS_HEAD_MISSING.Error() + "and" + defines.CLINET_ID_MISSING.Error())
            return
        }
        client_id = tmp

        tmp2, err := request.BodyParameter("client_secret")
        if err != nil {
            response.WriteErrorString(http.StatusBadRequest, defines.CLIENT_SECRET_MISSING.Error())
            return
        }
        client_secret = tmp2
    } else {
        var err error = nil
        client_id, client_secret, err = parseBasicInfo(basic)
        if err != nil {
            response.WriteErrorString(http.StatusBadRequest, err.Error())
        }
    }

    //check client_id and client_secret
    secret, err := auth.ClientManager.QuerySecret(client_id)
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.CHECK_CLIENT_ID_ERROR.Error())
        return
    }

    if client_secret != secret {
        response.WriteErrorString(http.StatusUnauthorized, defines.CLINET_SECRET_NOT_MATCH.Error())
        return
    }

    errCode := auth.EventListener(client_id, defines.RequestRefreshTokenEvent)
    if errCode != nil {
        response.WriteError(errCode.HttpStatus, errCode)
    }

    refresh_token, err := request.BodyParameter("refresh_token")
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.REFRESH_TOKEN_MISSING.Error())
        return
    }

    client_id_saved, err := auth.DataManager.Get(refresh_token_prefix + refresh_token)
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.REFRESH_TOKEN_NOT_FOUND.Error())
        return
    }

    if client_id != client_id_saved {
        response.WriteErrorString(http.StatusBadRequest, defines.CHECK_CLIENT_ID_ERROR.Error())
        return
    }

    //与请求authorization code时使用的redirect_uri相同。某些资源（API）不需要此参数。
    //redirect_uri, err := request.BodyParameter("redirect_uri")
    accessToken, err := generateToken(client_id, client_secret, defines.AccessTokenExpireTime)
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.GENERATE_ACCESSTOKEN_ERROR.Error())
        return
    }

    token := defines.Token{
        AccessToken: accessToken,
        TokenType: "bearer",
        ExpiresIn: int(defines.AccessTokenExpireTime),
        Scope: "",
    }

    saveToken(auth.DataManager, client_id, token.AccessToken, token.RefreshToken)

    tokenByte, err := json.Marshal(token)
    if err != nil {
        response.WriteErrorString(http.StatusBadRequest, defines.INTERNAL_ERROR.Error())
        return
    }

    response.Write(tokenByte)
}

func saveToken(dm defines.DataManager, client_id, access_token, refresh_token string) {

    if access_token != "" {
        dm.Set(access_token_prefix + access_token, client_id, defines.AccessTokenExpireTime) //1 hour
    }

    if refresh_token != "" {
        dm.Set(refresh_token_prefix + refresh_token, client_id, defines.RefreshTokenExpireTime) //30 day
    }
}

func parseBasicInfo(authorization string) (string, string, error) {
    //strs := strings.Split(authorization, " ")
    //size := len(strs)
    //basicStr := ""
    //if size == 0 {
    //    return "", "", defines.AUTHORIZATION_BASIC_ERROR
    //} else if size == 1 {
    //    basicStr = strs[0]
    //} else {
    //    basicStr = strs[1]
    //}

    basicStr := ""
    if len(authorization) > 5 && strings.ToUpper(authorization[0:6]) == "BASIC " {
        basicStr = authorization[6:]
    } else {
        basicStr = authorization
    }

    bytes, err := base64.StdEncoding.DecodeString(basicStr)
    if err != nil {
        return "", "", defines.AUTHORIZATION_BASIC_ERROR
    }

    basicStr = string(bytes)

    strs := strings.Split(basicStr, ":")
    if len(strs) < 2 {
        return "", "", defines.AUTHORIZATION_BASIC_ERROR
    }

    return strs[0], strs[1], nil
}