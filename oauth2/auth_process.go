/*
 * Copyright (C) 2019-2024, Xiongfa Li.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package oauth2

import (
	"encoding/base64"
	"github.com/xfali/oauth2/v2/constants"
	"github.com/xfali/oauth2/v2/datas"
	"github.com/xfali/oauth2/v2/errcodes"
	"strings"
)

func saveToken(dm datas.DataManager, access_data, access_token, refresh_data, refresh_token string) *errcodes.ErrCode {
	if refresh_token != "" {
		err := dm.SaveRefreshToken(refresh_data, refresh_token, constants.RefreshTokenExpireTime)
		if err != nil {
			return errcodes.SaveRefreshTokenError
		}
	}

	if access_token != "" {
		err := dm.SaveAccessToken(access_data, access_token, constants.AccessTokenExpireTime)
		if err != nil {
			return errcodes.SaveAccessTokenError
		}
	}

	return nil
}

func parseBasicInfo(authorization string) (string, string, *errcodes.ErrCode) {
	basicStr := ""
	if len(authorization) > 5 && strings.ToUpper(authorization[0:6]) == "BASIC " {
		basicStr = authorization[6:]
	} else {
		basicStr = authorization
	}

	bytes, err := base64.StdEncoding.DecodeString(basicStr)
	if err != nil {
		return "", "", errcodes.AuthorizationBasicError
	}

	basicStr = string(bytes)

	strs := strings.Split(basicStr, ":")
	if len(strs) < 2 {
		return "", "", errcodes.AuthorizationBasicError
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
