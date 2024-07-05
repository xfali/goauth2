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

package test

import (
	"github.com/gin-gonic/gin"
	"github.com/xfali/oauth2/v2/oauth2"
	"github.com/xfali/oauth2/v2/servers"
	"net/http"
	"testing"
)

func TestGin(t *testing.T) {
	ctx := oauth2.New()
	cliInfo, _ := ctx.ClientManager.CreateClient()
	t.Log(cliInfo)
	ctx.UserManager.CreateUser("admin", "admin")
	srv := servers.NewGinServer(ctx)
	r := gin.New()
	srv.RunWithEngine(r)

	s := http.Server{
		Addr:    ":8080",
		Handler: r,
	}
	s.ListenAndServe()
}
