/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package buildin

import (
	"github.com/xfali/goid"
	"github.com/xfali/oauth2/defines"
	"errors"
	"sync"
)

type DefaultClientManager struct {
	mutex sync.Mutex
	db    map[string]string
	sf    *goid.SnowFlake
}

func NewDefaultClientManager() *DefaultClientManager {
	return &DefaultClientManager{db: map[string]string{}, sf: goid.NewSnowFlake()}
}

func (cm *DefaultClientManager) CreateClient() (defines.ClientInfo, error) {
	id, _ := cm.sf.NextId()
	ci := defines.ClientInfo{
		ClientId:     id.Compress().String(),
		ClientSecret: goid.RandomId(32),
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

	secret := goid.RandomId(32)

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
