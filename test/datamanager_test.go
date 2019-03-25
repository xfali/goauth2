/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package test

import (
    "testing"
    "time"
    "github.com/xfali/oauth2/buildin"
)


func TestDataManager(t *testing.T) {
    dm := buildin.NewDefaultDataManager(0)

    dm.Set("123", "456", time.Second)

    v1, _ := dm.Get("123")
    t.Logf("value is %s\n", v1)

    time.Sleep(time.Second)

    v2, _ := dm.Get("123")
    t.Logf("After 1 second value is %s\n", v2)

    time.Sleep(time.Millisecond)

    v3, _ := dm.Get("123")
    t.Logf("After 1 second 1 Millisecond value is %s\n", v3)
}
