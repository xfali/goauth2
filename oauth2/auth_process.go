/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package oauth2

import (
    "encoding/base64"
    "github.com/xfali/oauth2/defines"
    "strings"
)


func saveToken(dm defines.DataManager, access_data, access_token, refresh_data, refresh_token string) *defines.ErrCode {
    if refresh_token != "" {
        err := dm.SaveRefreshToken(refresh_data, refresh_token, defines.RefreshTokenExpireTime)
        if err != nil {
            return defines.SAVE_REFRESHTOKEN_ERROR
        }
    }

    if access_token != "" {
        err := dm.SaveAccessToken(access_data, access_token, defines.AccessTokenExpireTime)
        if err != nil {
            return defines.SAVE_ACCESSTOKEN_ERROR
        }
    }

    return nil
}

func parseBasicInfo(authorization string) (string, string, *defines.ErrCode) {
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

func parseBearerInfo(authorization string) (string, error) {
    bearerStr := ""
    if len(authorization) > 6 && strings.ToUpper(authorization[0:7]) == "BEARER " {
        bearerStr = authorization[7:]
    } else {
        bearerStr = authorization
    }
    return bearerStr, nil
}
