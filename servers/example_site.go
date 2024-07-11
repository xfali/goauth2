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

package servers

import (
	"context"
	"github.com/xfali/oauth2/v2/constants"
	"github.com/xfali/oauth2/v2/entities"
	"github.com/xfali/oauth2/v2/errcodes"
	http2 "github.com/xfali/oauth2/v2/rpc/http"
	"io"
	"net/http"
	"strings"
	"time"
)

type SimpleSite struct {
	cli                    *http2.HttpClient
	clientId, clientSecret string
	authProcessor          AuthProcessor
}

type AuthProcessor interface {
	OnGrantTokenSuccess(token *entities.Token, w http.ResponseWriter, r *http.Request)
	OnGrantTokenFailed(err error, w http.ResponseWriter, r *http.Request)

	ExtractToken(r *http.Request) (string, error)
}

func NewSimpleSite(clientId, clientSecret string, cli *http2.HttpClient) *SimpleSite {
	ret := &SimpleSite{
		cli:           cli,
		clientId:      clientId,
		clientSecret:  clientSecret,
		authProcessor: &defaultAuthProcessor{},
	}
	return ret
}

func (s *SimpleSite) LoginHtml(loginUrl string, w http.ResponseWriter, r *http.Request) {
	htmlStr := LoginHtml
	param := loginUrl + "?" + r.URL.RawQuery
	htmlStr = strings.Replace(htmlStr, "LOGIN_API_PATH", param, 1)

	_, _ = io.WriteString(w, htmlStr)
}

func (s *SimpleSite) Login(ctx context.Context, authUserPasswordUrl, authorizeHtmlUrl string, w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" {
		w.WriteHeader(errcodes.UsernameMissing.HttpStatus)
		_, _ = w.Write([]byte(errcodes.UsernameMissing.Error()))
		return
	}
	if password == "" {
		w.WriteHeader(errcodes.PasswordMissing.HttpStatus)
		_, _ = w.Write([]byte(errcodes.PasswordMissing.Error()))
		return
	}
	token, err := s.cli.GrantByPassword(ctx, authUserPasswordUrl, s.clientId, s.clientSecret, username, password)
	if err != nil {
		s.authProcessor.OnGrantTokenFailed(err, w, r)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	s.authProcessor.OnGrantTokenSuccess(token, w, r)
	authorizeHtmlUrl = authorizeHtmlUrl + "?" + r.URL.RawQuery
	http.Redirect(w, r, authorizeHtmlUrl, http.StatusFound)
}

func (s *SimpleSite) AuthorizeHtml(authorizeUrl string, w http.ResponseWriter, r *http.Request) {
	htmlStr := AuthorizeHtml
	param := authorizeUrl + "?" + r.URL.RawQuery
	htmlStr = strings.Replace(htmlStr, "AUTHORIZE_API_PATH", param, 1)

	_, _ = io.WriteString(w, htmlStr)
}

func (s *SimpleSite) Authorize(ctx context.Context, authorizeUrl string, w http.ResponseWriter, r *http.Request) {
	authorizeUrl = authorizeUrl + "?" + r.URL.RawQuery
	http.Redirect(w, r, authorizeUrl, http.StatusFound)
	//token, err := s.authProcessor.ExtractToken(r)
	//if err != nil {
	//	w.WriteHeader(http.StatusUnauthorized)
	//	_, _ = w.Write([]byte(errcodes.AccessTokenMissing.Error()))
	//	return
	//}
	//err = s.cli.Authorize(ctx, authorizeUrl, token)
	//if err != nil {
	//	w.WriteHeader(http.StatusUnauthorized)
	//	_, _ = w.Write([]byte(errcodes.AuthenticateAccessTokenError.Error()))
	//	return
	//}
}

type defaultAuthProcessor struct {
}

func (l *defaultAuthProcessor) OnGrantTokenSuccess(token *entities.Token, w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "Authorization",
		Value:    token.AccessToken,
		Path:     "/",
		HttpOnly: false,
		Expires:  time.Now().Add(constants.AccessTokenExpireTime),
	})
}

func (l *defaultAuthProcessor) OnGrantTokenFailed(err error, w http.ResponseWriter, r *http.Request) {

}

func (l *defaultAuthProcessor) ExtractToken(r *http.Request) (string, error) {
	c, err := r.Cookie("Authorization")
	if err != nil {
		return "", errcodes.AccessTokenMissing
	}
	return c.Value, nil
}
