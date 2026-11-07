//go:build darwin

package main

import "errors"

// The Secure Enclave, when clevr-se-helper is installed beside this binary.
func platformChip() (chip, error) {
	h := seHelperPath()
	if h == "" {
		return nil, errors.New("clevr-se-helper is not installed beside the custody")
	}
	return seChip{helper: h}, nil
}

// The chip a key file names, to open the key it holds.
func chipNamed(kind string) (chip, error) {
	if kind != chipSecureEnclave {
		return nil, errors.New("this Mac holds no " + kind + " key")
	}
	return platformChip()
}
