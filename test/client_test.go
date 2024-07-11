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
		w.WriteField("client_id", "12L0dnUwdmK")
		w.WriteField("client_secret", "VUq_6pxbc5msKxBJggCih9-UjhciE7DZY-RB4XRrnL4=")
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

	t.Run("test token", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://localhost:8080/oauth2/authenticate", nil)
		req.Header.Add("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiIxMkwwZG5Vd2RtSyIsImV4cCI6MTcyMDUyMzEzOCwiaWF0IjoxNzIwNTE1OTM4fQ.CGtkv_9PphMQkMR5-1GIYjPERPeH2NH4sdeq0CY_JtE")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		io.Copy(os.Stdout, resp.Body)
		if resp.StatusCode != 200 {
			t.Fatal("Not 200 ", resp.StatusCode)
		}
	})
}
