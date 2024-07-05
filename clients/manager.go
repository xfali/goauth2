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

package clients

import "github.com/xfali/oauth2/v2/entities"

type ClientManager interface {
	// Deprecated: 仅作为测试使用
	CreateClient() (entities.ClientInfo, error)

	// Deprecated: 仅作为测试使用
	UpdateClient(clientId string) (string, error)

	// Deprecated: 仅作为测试使用
	DeleteClient(clientId string) error

	// QuerySecret 根据client id查询client secret
	QuerySecret(clientId string) (string, error)

	// CheckScope 查询client id是否可授权scope，可授权返回true
	CheckScope(clientId string, respType string, scope string) bool

	// CheckDomainName 检查域名
	CheckDomainName(clientId string, domainName string) error
}
