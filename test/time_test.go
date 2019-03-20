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
)

func TestTimer(t *testing.T) {
    timer := time.NewTimer(time.Second)
    for {
        select {
        case <-timer.C:
            fmt.Println("timeout")
        }
    }
}

func TestTicker(t *testing.T) {
    timer := time.NewTicker(time.Second)
    for {
        select {
        case <-timer.C:
            fmt.Println("timeout")
        }
    }
}
