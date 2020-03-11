package main

import (
	"math/rand"
	"time"
)

var (
	letterRunes = []rune("abcdefghijklmnopqrstuvwxyz123456789")
)

func init() {
	rand.Seed(time.Now().Unix())
}

// RandomString generates a random string with prefix
func RandomString(prefix string, length int) string {
	b := make([]rune, length)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return prefix + string(b)
}