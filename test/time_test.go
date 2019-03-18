/**
 * Copyright (C) 2019, Xiongfa Li.
 * All right reserved.
 * @author xiongfa.li
 * @version V1.0
 * Description: 
 */

package test

import (
    "fmt"
    "testing"
    "time"
    "oauth2/buildin"
)

func TestTimer(t *testing.T) {
    //timer := time.NewTicker(time.Second)
    timer := time.NewTimer(time.Second)
    for {
        select {
        case <-timer.C:
            fmt.Println("timeout")
        }
    }
}

func TestDataManager(t *testing.T) {
    dm := buildin.NewDefaultDataManager(0)

    dm.Set("123", "456", time.Second)

    t.Logf("value is %s\n", dm.Get("123"))

    time.Sleep(time.Second)

    t.Logf("After 1 second value is %s\n", dm.Get("123"))

    time.Sleep(time.Millisecond)

    t.Logf("After 1 second 1 Millisecond value is %s\n", dm.Get("123"))
}
