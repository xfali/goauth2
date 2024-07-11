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
	"github.com/gin-gonic/gin"
	"github.com/xfali/oauth2/v2/oauth2"
	"github.com/xfali/xlog"
	"net/http"
)

type GinServer struct {
	logger xlog.Logger
	ctx    *oauth2.OAuth2Context

	logHttpInfo bool
	addr        string
}

func NewGinServer(ctx *oauth2.OAuth2Context) *GinServer {
	ret := &GinServer{
		logger: xlog.GetLogger(),
		ctx:    ctx,
	}
	return ret
}

func (s *GinServer) wrapRouteFunction(function func(request *http.Request, response http.ResponseWriter)) gin.HandlerFunc {
	return func(context *gin.Context) {
		function(context.Request, context.Writer)
	}
}

func (s *GinServer) RunWithEngine(addr string, engine *gin.Engine) {
	group := engine.Group("/oauth2")

	group.GET("/authorize", s.wrapRouteFunction(s.ctx.Authorize))
	group.GET("/authorize/web", s.wrapRouteFunction(s.ctx.AuthorizeWeb))
	group.POST("/token", s.wrapRouteFunction(s.ctx.Token))
	group.GET("/authenticate", s.wrapRouteFunction(s.ctx.Authenticate))
	group.DELETE("/token", s.wrapRouteFunction(s.ctx.Revoke))

	s.ctx.CallbackUrl = addr + "/" + group.BasePath() + "/authorize/web"
}
