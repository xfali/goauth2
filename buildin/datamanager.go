/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package buildin

import (
	"time"
	"sync"
	"runtime"
	"errors"
)

type dataEntity struct {
	value      interface{}
	expireTime time.Duration
}

type DefaultDataManager struct {
	PurgeInterval time.Duration
	db            map[interface{}]dataEntity
	stop          chan bool
	mutex         sync.Mutex
}

func NewDefaultDataManager(PurgeInterval time.Duration) *DefaultDataManager {
	if PurgeInterval <= 0 {
		PurgeInterval = 0
	}
	ret := &DefaultDataManager{
		db:            map[interface{}]dataEntity{},
		stop:          make(chan bool),
		PurgeInterval: PurgeInterval,
	}

	go func() {
		if ret.PurgeInterval > 0 {
			timer := time.NewTicker(ret.PurgeInterval)
			for {
				select {
				case <-ret.stop:
					return
				case <-timer.C:
					ret.purge()
				}
			}
		} else {
			for {
				select {
				case <-ret.stop:
					return
				default:

				}
				ret.purge()

				runtime.Gosched()
			}
		}
	}()

	return ret
}

func (dm *DefaultDataManager) purge() {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	now := time.Duration(time.Now().UnixNano())
	for k, v := range dm.db {
		if v.expireTime <= now {
			delete(dm.db, k)
		}
	}
}

func (dm *DefaultDataManager) Close() {
	close(dm.stop)
}

func (dm *DefaultDataManager) innerSet(key, value interface{}, expireIn time.Duration) error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	time := expireIn + time.Duration(time.Now().UnixNano())
	dm.db[key] = dataEntity{value: value, expireTime: time}

	return nil
}

func (dm *DefaultDataManager) innerGet(key interface{}) interface{} {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	v, ok := dm.db[key]
	if ok {
		return v.value
	} else {
		return nil
	}
}

func (dm *DefaultDataManager) innerDel(key interface{}) {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()
	delete(dm.db, key)
}

func (dm *DefaultDataManager) Set(key, value string, expireIn time.Duration) error {
	return dm.innerSet(key, value, expireIn)
}

func (dm *DefaultDataManager) Get(key string) (string, error) {
	v := dm.innerGet(key)
	if v == nil {
		return "", errors.New("Not found")
	} else {
		return v.(string), nil
	}
}

func (dm *DefaultDataManager) Del(key string) error {
	dm.innerDel(key)
	return nil
}
