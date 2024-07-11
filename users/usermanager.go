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

package users

import (
	"github.com/xfali/oauth2/v2/errcodes"
	"net/http"
)

type DefaultUserManager struct {
	db           map[string]string
	loginUrl     string
	authorizeUrl string
}

func NewDefaultUserManager(loginUrl, authorizeUrl string) *DefaultUserManager {
	ret := &DefaultUserManager{db: map[string]string{}, loginUrl: loginUrl, authorizeUrl: authorizeUrl}
	return ret
}

func (um *DefaultUserManager) CheckUser(username, password string) error {
	if um.db[username] == password {
		return nil
	} else {
		return errcodes.PasswordNotMatch
	}
}

func (um *DefaultUserManager) CreateUser(username, password string) error {
	um.db[username] = password
	return nil
}

func (um *DefaultUserManager) UserAuthorize(r *http.Request) (string, error) {
	_, err := r.Cookie("Authorization")
	if err != nil {
		return um.loginUrl, nil
	} else {
		return um.authorizeUrl, nil
	}
}

func (um *DefaultUserManager) ExtractToken(r *http.Request) (string, error) {
	c, err := r.Cookie("Authorization")
	if err != nil {
		return "", errcodes.AccessTokenMissing
	} else {
		return c.Value, nil
	}
}
