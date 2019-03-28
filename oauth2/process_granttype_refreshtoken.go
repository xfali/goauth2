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
    "github.com/xfali/oauth2/defines"
    "time"
)

func ProcessGrantTypeRefreshToken(auth *OAuth2, request *restful.Request, response *restful.Response) {
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

    errCode := auth.EventListener(client_id, defines.RequestRefreshTokenEvent)
    if errCode != nil {
        response.WriteError(errCode.HttpStatus, errCode)
        return
    }

    refresh_token, err := request.BodyParameter("refresh_token")
    if err != nil {
        response.WriteErrorString(defines.REFRESH_TOKEN_MISSING.HttpStatus, defines.REFRESH_TOKEN_MISSING.Error())
        return
    }

    jwt_client_id, err := parseToken(secret, refresh_token)
    if err != nil {
        response.WriteErrorString(defines.TOKEN_ERROR.HttpStatus, defines.TOKEN_ERROR.Error())
        return
    }

    if client_id != jwt_client_id {
        response.WriteErrorString(defines.CHECK_CLIENT_ID_ERROR.HttpStatus, defines.CHECK_CLIENT_ID_ERROR.Error())
        return
    }

    token_data, err := auth.DataManager.GetRefreshToken(refresh_token)
    if err != nil  || token_data == "" {
        response.WriteErrorString(defines.REFRESH_TOKEN_NOT_FOUND.HttpStatus, defines.REFRESH_TOKEN_NOT_FOUND.Error())
        return
    }

    //FIXME 不需要比较缓存中的数据？
    //if client_id != token_data {
    //    response.WriteErrorString(defines.CHECK_CLIENT_ID_ERROR.HttpStatus, defines.CHECK_CLIENT_ID_ERROR.Error())
    //    return
    //}

    //与请求authorization code时使用的redirect_uri相同。某些资源（API）不需要此参数。
    //redirect_uri, err := request.BodyParameter("redirect_uri")
    accessToken, err := generateToken(client_id, client_secret, defines.AccessTokenExpireTime)
    if err != nil {
        response.WriteErrorString(defines.GENERATE_ACCESSTOKEN_ERROR.HttpStatus, defines.GENERATE_ACCESSTOKEN_ERROR.Error())
        return
    }

    token := defines.Token{
        AccessToken: accessToken,
        TokenType:   "bearer",
        ExpiresIn:   int(defines.AccessTokenExpireTime / time.Second),
        Scope:       "",
    }

    saveErr := saveToken(auth.DataManager, client_id, token.AccessToken, client_id, token.RefreshToken)
    if saveErr != nil {
        response.WriteErrorString(saveErr.HttpStatus, saveErr.Error())
        return
    }

    tokenByte, err := json.Marshal(&token)
    if err != nil {
        response.WriteErrorString(defines.INTERNAL_ERROR.HttpStatus, defines.INTERNAL_ERROR.Error())
        return
    }

    response.Write(tokenByte)
}
