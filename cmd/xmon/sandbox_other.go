//go:build !linux

package main

import "errors"

func cmdSandbox(args []string) error {
	return errors.New("__sandbox is only used on Linux")
}
