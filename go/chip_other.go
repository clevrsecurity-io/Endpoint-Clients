//go:build !darwin && !windows

package main

import "errors"

// No chip here: a TPM on Linux is not used (yet), the key stays in software.
func platformChip() (chip, error) {
	return nil, errors.New("the machine key is kept in a chip on macOS and Windows only")
}

func chipNamed(kind string) (chip, error) {
	return nil, errors.New("this system holds no " + kind + " key")
}
