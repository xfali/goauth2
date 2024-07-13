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
	"fmt"
	"github.com/xfali/oauth2/v2/entities"
	"github.com/xfali/oauth2/v2/errcodes"
	"github.com/xfali/oauth2/v2/oauth2"
	"github.com/xfali/oauth2/v2/token"
	"github.com/xfali/xlog"
	"io"
	"net/http"
	"net/url"
	"strings"
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
	formData := url.Values{}
	formData.Set("grant_type", oauth2.GrantTypePassword)
	formData.Set("client_id", clientId)
	formData.Set("client_secret", clientSecret)
	formData.Set("username", username)
	formData.Set("password", password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.Errorln(err)
		return nil, err
	}
	defer resp.Body.Close()

	body := bytes.NewBuffer(nil)
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

func (c *HttpClient) RevokeToken(ctx context.Context, endpoint string, clientId, clientSecret, token string, tokenType string) error {
	formData := url.Values{}
	formData.Set("client_id", clientId)
	formData.Set("client_secret", clientSecret)
	formData.Set("token", token)
	formData.Set("token_type_hint", tokenType)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.Errorln(err)
		return err
	}
	defer resp.Body.Close()

	body := bytes.NewBuffer(nil)
	_, err = io.Copy(body, resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("%s", body.String())
}
