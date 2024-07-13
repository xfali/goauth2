/*
 * Copyright (C) 2024, Xiongfa Li.
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

package token

import (
	"github.com/xfali/oauth2/v2/configs"
	"github.com/xfali/oauth2/v2/errcodes"
	"net/http"
	"strings"
)

type defaultExtractor struct {
}

func NewExtractor() *defaultExtractor {
	return &defaultExtractor{}
}

func (e *defaultExtractor) ExtractToken(r *http.Request) (string, error) {
	bearer := r.Header.Get(configs.OAuth2TokenAuthorizationKey)
	if bearer == "" {
		return "", errcodes.AccessTokenMissing
	}
	return ParseBearerInfo(bearer)
}

func ParseBearerInfo(authorization string) (string, error) {
	bearerStr := ""
	if len(authorization) > 6 && strings.ToUpper(authorization[0:7]) == "BEARER " {
		bearerStr = authorization[7:]
	} else {
		bearerStr = authorization
	}
	return bearerStr, nil
}
