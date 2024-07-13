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
	"encoding/json"
	"github.com/xfali/oauth2/v2/clients"
	"github.com/xfali/oauth2/v2/constants"
	"github.com/xfali/oauth2/v2/datas"
	"github.com/xfali/oauth2/v2/errcodes"
	"github.com/xfali/oauth2/v2/events"
	"github.com/xfali/oauth2/v2/token"
	"github.com/xfali/oauth2/v2/users"
	"github.com/xfali/xlog"
	"io"
	"net/http"
	"time"
)

const (
	ResponseTypeCode  = "code"
	ResponseTypeToken = "token"

	GrantTypeCode              = "authorization_code"
	GrantTypeImplicit          = "implicit"
	GrantTypePassword          = "password"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeDeviceCode        = "device code"
	GrantTypeRefreshToken      = "refresh_token"
)

type ResponseTypeFunc func(auth *OAuth2Context, request *http.Request, response http.ResponseWriter) error
type GrantTypeFunc func(auth *OAuth2Context, request *http.Request, response http.ResponseWriter) error
type Writer interface {
	Write(w http.ResponseWriter, o interface{}) error
	WriteError(w http.ResponseWriter, code *errcodes.ErrCode) error
}

type OAuth2Context struct {
	UserManager   users.UserManager
	ClientManager clients.ClientManager
	DataManager   datas.DataManager
	EventListener events.EventListener
	Extractor     token.Extractor

	CodeExpireTime time.Duration
	CallbackUrl    string

	logger xlog.Logger

	respWriter Writer

	processRespMap    map[string]ResponseTypeFunc
	processRespWebMap map[string]ResponseTypeFunc
	processGrantMap   map[string]GrantTypeFunc
}

func New() *OAuth2Context {
	return NewWithWebCode("", "")
}

func NewWithWebCode(loginUrl, authorizeUrl string) *OAuth2Context {
	ret := &OAuth2Context{
		logger:            xlog.GetLogger(),
		UserManager:       users.NewDefaultUserManager(loginUrl, authorizeUrl),
		ClientManager:     clients.NewDefaultClientManager(),
		DataManager:       datas.NewDefaultDataManager(0),
		Extractor:         token.NewExtractor(),
		EventListener:     events.DefaultEventListener,
		CodeExpireTime:    constants.AuthorizationCodeExpireTime,
		respWriter:        &defaultWriter{},
		processRespMap:    map[string]ResponseTypeFunc{},
		processRespWebMap: map[string]ResponseTypeFunc{},
		processGrantMap:   map[string]GrantTypeFunc{},
	}

	ret.RegisterRespProcessor(ResponseTypeCode, ProcessRespTypeCode)
	ret.RegisterRespWebProcessor(ResponseTypeCode, ProcessRespTypeWebCode)
	//It is generally not recommended to use the implicit flow
	//ret.RegisterRespProcessor(RESPONSE_TYPE_TOKEN, ProcessRespTypeToken)
	//ret.RegisterRespWebProcessor(RESPONSE_TYPE_CODE, ProcessRespTypeWebCode)
	ret.RegisterGrantProcessor(GrantTypeCode, ProcessGrantTypeCode)
	ret.RegisterGrantProcessor(GrantTypePassword, ProcessGrantTypePassword)
	ret.RegisterGrantProcessor(GrantTypeClientCredentials, ProcessGrantTypeClientCredentials)
	ret.RegisterGrantProcessor(GrantTypeRefreshToken, ProcessGrantTypeRefreshToken)

	return ret
}

func (auth *OAuth2Context) Close() {
	auth.DataManager.Close()
}

func (auth *OAuth2Context) RegisterRespProcessor(resp_type string, function ResponseTypeFunc) {
	auth.processRespMap[resp_type] = function
}

func (auth *OAuth2Context) RegisterRespWebProcessor(resp_type string, function ResponseTypeFunc) {
	auth.processRespWebMap[resp_type] = function
}

func (auth *OAuth2Context) RegisterGrantProcessor(grant_type string, function GrantTypeFunc) {
	auth.processGrantMap[grant_type] = function
}

func (auth *OAuth2Context) Authorize(request *http.Request, response http.ResponseWriter) {
	query := request.URL.Query()
	response_type := query.Get("response_type")

	function := auth.processRespMap[response_type]
	if function != nil {
		function(auth, request, response)
		return
	}

	auth.logger.Errorf("authorize response type %s not support\n", response_type)
	_ = auth.respWriter.WriteError(response, errcodes.ResponseTypeNotSupport)
}

func (auth *OAuth2Context) AuthorizeWeb(request *http.Request, response http.ResponseWriter) {
	query := request.URL.Query()
	response_type := query.Get("response_type")

	function := auth.processRespWebMap[response_type]
	if function != nil {
		function(auth, request, response)
		return
	}

	auth.logger.Errorf("authorizeWeb response type %s not support\n", response_type)
	_ = auth.respWriter.WriteError(response, errcodes.ResponseTypeNotSupport)
}

func (auth *OAuth2Context) Token(request *http.Request, response http.ResponseWriter) {
	grant_type := request.FormValue("grant_type")
	if grant_type == "" {
		_ = auth.respWriter.WriteError(response, errcodes.GrantTypeMissing)
		return
	}

	function := auth.processGrantMap[grant_type]
	if function != nil {
		err := function(auth, request, response)
		if err != nil {
			auth.logger.Errorln("token error: ", err)
		}
		return
	}

	auth.logger.Errorf("Token grant type %s not support\n", grant_type)
	_ = auth.respWriter.WriteError(response, errcodes.GrantTypeNotSupport)
}

func (auth *OAuth2Context) Authenticate(request *http.Request, response http.ResponseWriter) {
	err := ProcessAccessToken(auth, request, response)
	if err != nil {
		auth.logger.Errorln("authenticate failed: ", err)
	}
}

func (auth *OAuth2Context) Revoke(request *http.Request, response http.ResponseWriter) {
	err := ProcessRevokeToken(auth, request, response)
	if err != nil {
		auth.logger.Errorln("revoke failed: ", err)
	}
}

/*
func (auth *OAuth2Context) createClient(request *restful.Request, response *restful.Response) {
    clientInfo, err := auth.ClientManager.CreateClient()
    if err != nil {
        response.WriteError(http.StatusInternalServerError, err)
    }
    b, err := json.Marshal(clientInfo)
    if err != nil {
        response.WriteError(http.StatusInternalServerError, err)
    }
    response.Write(b)
}

func (auth *OAuth2Context) updateClient(request *restful.Request, response *restful.Response) {
    client_id := request.PathParameter("client_id")
    secret, err := auth.ClientManager.UpdateClient(client_id)
    if err != nil {
        response.WriteError(http.StatusInternalServerError, err)
    }
    io.WriteString(response.ResponseWriter, secret)
}

func (auth *OAuth2Context) deleteClient(request *restful.Request, response *restful.Response) {
    client_id := request.PathParameter("client_id")
    err := auth.ClientManager.DeleteClient(client_id)
    if err != nil {
        response.WriteError(http.StatusInternalServerError, err)
    }
    response.WriteHeader(http.StatusOK)
}
*/

type defaultWriter struct {
}

func (dw *defaultWriter) Write(w http.ResponseWriter, o interface{}) error {
	if o == nil {
		return nil
	}
	if s, ok := o.(string); ok {
		_, err := io.WriteString(w, s)
		return err
	} else {
		v, err := json.Marshal(o)
		if err != nil {
			return err
		}
		_, err = w.Write(v)
		return err
	}
}

func (dw *defaultWriter) WriteError(w http.ResponseWriter, code *errcodes.ErrCode) error {
	if code != nil {
		w.WriteHeader(code.HttpStatus)
		_, err := w.Write([]byte(code.Error()))
		return err
	}
	return nil
}
