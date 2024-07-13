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

package http

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/xfali/oauth2/v2/entities"
	"github.com/xfali/oauth2/v2/errcodes"
	"github.com/xfali/oauth2/v2/oauth2"
	"github.com/xfali/oauth2/v2/token"
	"github.com/xfali/xlog"
	"io"
	"mime/multipart"
	"net/http"
)

type HttpClient struct {
	logger   xlog.Logger
	client   *http.Client
	attacher token.Attacher
}

func NewHttpClient(client *http.Client, attacher token.Attacher) *HttpClient {
	if client == nil {
		client = http.DefaultClient
	}

	ret := &HttpClient{
		logger: xlog.GetLogger(),
		client: client,
	}

	if attacher == nil {
		ret.attacher = token.NewAttacher()
	}
	return ret
}

func (c *HttpClient) GrantByPassword(ctx context.Context, endpoint string, clientId, clientSecret, username, password string) (*entities.Token, error) {
	body := bytes.NewBuffer(nil)
	w := multipart.NewWriter(body)
	err := w.WriteField("grant_type", oauth2.GrantTypePassword)
	if err != nil {
		return nil, err
	}
	err = w.WriteField("client_id", clientId)
	if err != nil {
		return nil, err
	}
	err = w.WriteField("client_secret", clientSecret)
	if err != nil {
		return nil, err
	}
	err = w.WriteField("username", username)
	if err != nil {
		return nil, err
	}
	err = w.WriteField("password", password)
	if err != nil {
		return nil, err
	}

	err = w.Close()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.Errorln(err)
		return nil, err
	}
	defer resp.Body.Close()

	body.Reset()
	_, err = io.Copy(body, resp.Body)
	if err != nil {
		return nil, err
	}

	ret := &entities.Token{}
	err = json.Unmarshal(body.Bytes(), ret)
	return ret, err
}

func (c *HttpClient) Authorize(ctx context.Context, endpoint string, token string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	err := c.attacher.AttachToken(req, token)
	if err != nil {
		c.logger.Errorln(err)
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.Errorln(err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		c.logger.Errorln("Not 200 ", resp.StatusCode)
		return errcodes.AuthenticateAccessTokenError
	}
	return nil
}
