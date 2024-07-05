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
	"bytes"
	"github.com/xfali/oauth2/v2/oauth2"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"testing"
)

func TestClient(t *testing.T) {
	t.Run("get token", func(t *testing.T) {
		body := bytes.NewBuffer(nil)
		w := multipart.NewWriter(body)
		w.WriteField("grant_type", oauth2.GrantTypePassword)
		w.WriteField("client_id", "12KpwwdeAzY")
		w.WriteField("client_secret", "wJ7RYk4tGwAceAuCJ6W-rNdWQeGSNccA-waGywdNZhk=")
		w.WriteField("username", "admin")
		w.WriteField("password", "admin")

		w.Close()
		resp, err := http.Post("http://localhost:8080/oauth2/token", w.FormDataContentType(), body)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		io.Copy(os.Stdout, resp.Body)
	})
}
