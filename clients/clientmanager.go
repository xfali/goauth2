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

package clients

import (
	"errors"
	"github.com/xfali/goutils/idUtil"
	"github.com/xfali/oauth2/v2/entities"
	"sync"
)

var (
	sf = idUtil.NewSnowFlake()
)

type DefaultClientManager struct {
	mutex sync.Mutex
	db    map[string]string
}

func NewDefaultClientManager() *DefaultClientManager {
	return &DefaultClientManager{db: map[string]string{}}
}

func (cm *DefaultClientManager) CreateClient(ci entities.ClientInfo) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cm.db[ci.ClientId] = ci.ClientSecret
	return nil
}

func GenerateClientInfo() entities.ClientInfo {
	id, _ := sf.NextId()
	return entities.ClientInfo{
		ClientId:     id.Compress().String(),
		ClientSecret: idUtil.RandomId(32),
	}
}

func (cm *DefaultClientManager) QuerySecret(clientId string) (string, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	secret, ok := cm.db[clientId]
	if !ok {
		return "", errors.New("client id not found")
	}

	return secret, nil
}

func (cm *DefaultClientManager) UpdateClient(clientId string) (string, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if _, ok := cm.db[clientId]; !ok {
		return "", errors.New("client id not found")
	}

	secret := idUtil.RandomId(32)

	cm.db[clientId] = secret

	return secret, nil
}

func (cm *DefaultClientManager) DeleteClient(clientId string) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if _, ok := cm.db[clientId]; !ok {
		return errors.New("client id not found")
	}
	delete(cm.db, clientId)
	return nil
}

func (cm *DefaultClientManager) CheckScope(client_id string, respType string, scope string) bool {
	return true
}

func (cm *DefaultClientManager) CheckDomainName(client_id string, domain_name string) error {
	return nil
}
