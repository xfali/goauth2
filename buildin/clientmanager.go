/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package buildin

import (
	"github.com/xfali/goutils/idUtil"
	"github.com/xfali/oauth2/defines"
	"errors"
	"sync"
)

type DefaultClientManager struct {
	mutex sync.Mutex
	db    map[string]string
	sf    *idUtil.SnowFlake
}

func NewDefaultClientManager() *DefaultClientManager {
	return &DefaultClientManager{db: map[string]string{}, sf: idUtil.NewSnowFlake()}
}

func (cm *DefaultClientManager) CreateClient() (defines.ClientInfo, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	id, _ := cm.sf.NextId()
	ci := defines.ClientInfo{
		ClientId:     id.Compress().String(),
		ClientSecret: idUtil.RandomId(32),
	}

	cm.db[ci.ClientId] = ci.ClientSecret
	return ci, nil
}

func (cm *DefaultClientManager)QuerySecret(clientId string) (string, error) {
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