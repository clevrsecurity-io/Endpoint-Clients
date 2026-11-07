//go:build windows

package main

// The machine key in the TPM, through the Microsoft Platform Crypto Provider:
// a persisted ECDSA P-256 key of the account the custody runs as (the
// service's virtual account), named in the key file, its private half never
// out of the TPM. A TPM 1.2, which has no ECDSA, or none at all, fails the
// creation and the custody keeps its key in software.
//
// Cross-compiled from macOS; never run on Windows nor against a TPM. The key
// lives in the virtual account's own key store: removing that account's
// profile loses it, and the machine then enrols again.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ncrypt                        = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procNCryptOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procNCryptExportKey           = ncrypt.NewProc("NCryptExportKey")
	procNCryptSignHash            = ncrypt.NewProc("NCryptSignHash")
	procNCryptDeleteKey           = ncrypt.NewProc("NCryptDeleteKey")
	procNCryptFreeObject          = ncrypt.NewProc("NCryptFreeObject")
)

const (
	msPlatformCryptoProvider = "Microsoft Platform Crypto Provider"
	ncryptECDSAP256          = "ECDSA_P256"
	bcryptECCPublicBlob      = "ECCPUBLICBLOB"
	ncryptSilentFlag         = 0x40
)

func platformChip() (chip, error) { return tpmChip{}, nil }

func chipNamed(kind string) (chip, error) {
	if kind != chipTPM {
		return nil, errors.New("this machine holds no " + kind + " key")
	}
	return tpmChip{}, nil
}

type tpmChip struct{}

func (tpmChip) kind() string { return chipTPM }

func ncryptErr(fn string, r uintptr) error {
	if r == 0 {
		return nil
	}
	return fmt.Errorf("%s: 0x%08x", fn, uint32(r))
}

func wide(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

func openPlatformProvider() (uintptr, error) {
	if err := ncrypt.Load(); err != nil {
		return 0, err
	}
	var prov uintptr
	r, _, _ := procNCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&prov)), uintptr(unsafe.Pointer(wide(msPlatformCryptoProvider))), 0)
	return prov, ncryptErr("NCryptOpenStorageProvider", r)
}

func (c tpmChip) create() (*chipKey, error) {
	prov, err := openPlatformProvider()
	if err != nil {
		return nil, err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		procNCryptFreeObject.Call(prov)
		return nil, err
	}
	name := "Clevr machine key " + hex.EncodeToString(rnd[:])
	var key uintptr
	r, _, _ := procNCryptCreatePersistedKey.Call(prov, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(wide(ncryptECDSAP256))), uintptr(unsafe.Pointer(wide(name))), 0, 0)
	if err := ncryptErr("NCryptCreatePersistedKey", r); err != nil {
		procNCryptFreeObject.Call(prov)
		return nil, err
	}
	r, _, _ = procNCryptFinalizeKey.Call(key, ncryptSilentFlag)
	if err := ncryptErr("NCryptFinalizeKey", r); err != nil {
		procNCryptDeleteKey.Call(key, 0)
		procNCryptFreeObject.Call(prov)
		return nil, err
	}
	k, err := c.keyFrom(key, name, "")
	if err != nil {
		procNCryptDeleteKey.Call(key, 0)
		procNCryptFreeObject.Call(prov)
		return nil, err
	}
	return k, nil
}

func (c tpmChip) open(kf machineKeyFile) (*chipKey, error) {
	if kf.Name == "" {
		return nil, errors.New("the key file names no TPM key")
	}
	prov, err := openPlatformProvider()
	if err != nil {
		return nil, err
	}
	var key uintptr
	r, _, _ := procNCryptOpenKey.Call(prov, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(wide(kf.Name))), 0, ncryptSilentFlag)
	if err := ncryptErr("NCryptOpenKey", r); err != nil {
		procNCryptFreeObject.Call(prov)
		return nil, err
	}
	k, err := c.keyFrom(key, kf.Name, kf.Pub)
	if err != nil {
		procNCryptFreeObject.Call(key)
		procNCryptFreeObject.Call(prov)
		return nil, err
	}
	return k, nil
}

// The key's public half, checked against the one the key file names when
// there is one, and its signer. The handles stay open as long as the custody.
func (tpmChip) keyFrom(key uintptr, name, want string) (*chipKey, error) {
	blobType := wide(bcryptECCPublicBlob)
	var n uint32
	r, _, _ := procNCryptExportKey.Call(key, 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0, uintptr(unsafe.Pointer(&n)), 0)
	if err := ncryptErr("NCryptExportKey", r); err != nil {
		return nil, err
	}
	if n == 0 || n > 1024 {
		return nil, errors.New("NCryptExportKey: no public key")
	}
	buf := make([]byte, n)
	r, _, _ = procNCryptExportKey.Call(key, 0, uintptr(unsafe.Pointer(blobType)), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(n), uintptr(unsafe.Pointer(&n)), 0)
	if err := ncryptErr("NCryptExportKey", r); err != nil {
		return nil, err
	}
	pub, err := eccPublicBlobToSPKI(buf[:n])
	if err != nil {
		return nil, err
	}
	if want != "" && pub != want {
		return nil, errors.New("the TPM's key is not the one the key file names")
	}
	var mu sync.Mutex
	sign, err := checkedSigner(pub, func(msg []byte) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		h := sha256.Sum256(msg)
		sig := make([]byte, 64)
		var got uint32
		r, _, _ := procNCryptSignHash.Call(key, 0, uintptr(unsafe.Pointer(&h[0])), uintptr(len(h)), uintptr(unsafe.Pointer(&sig[0])), uintptr(len(sig)), uintptr(unsafe.Pointer(&got)), ncryptSilentFlag)
		if err := ncryptErr("NCryptSignHash", r); err != nil {
			return nil, err
		}
		return sig[:got], nil
	})
	if err != nil {
		return nil, err
	}
	return &chipKey{pub: pub, name: name, sign: sign}, nil
}
