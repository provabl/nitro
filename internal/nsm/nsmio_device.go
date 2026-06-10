// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

//go:build linux && nsm

package nsm

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/fxamacker/cbor/v2"
)

// The NSM device speaks a CBOR-framed request/response protocol over a single
// ioctl. The ioctl argument is a struct of two iovecs (request, response); the
// driver reads the CBOR request from the first and writes the CBOR response into
// the second, updating the response iovec's length to the bytes actually written.
//
// The request is {"Attestation": {"user_data": null, "nonce": <bytes>,
// "public_key": null}}; the response is {"Attestation": {"document":
// <COSE_Sign1 bytes>}}.
//
// The ioctl number and struct layout are cross-checked against the known-good
// pure-Go binding github.com/hf/nsm (nsm.go / ioc/ioc.go) and AWS's
// aws-nitro-enclaves-nsm-api: magic 0x0A, nr 0, direction READ|WRITE, size =
// sizeof(the two-iovec message). This path can only be EXERCISED inside a Nitro
// enclave (the device exists nowhere else); it is compile-checked in CI and was
// validated on real Nitro hardware — see CHANGELOG / nitro#4.
const (
	// nsmIoctlMagic is the NSM driver's ioctl type byte ('A' would be 0x41; the
	// NSM driver uses 0x0A — confirmed against hf/nsm's ioctlMagic and the
	// aws-nitro-enclaves-nsm-api crate).
	nsmIoctlMagic = 0x0A

	// maxNSMResponse bounds the response buffer. Attestation documents are a few
	// KiB; hf/nsm uses 0x3000 (12 KiB) for the response pool. 16 KiB is a safe
	// upper bound.
	maxNSMResponse = 16 * 1024
)

// Linux asm-generic ioctl encoding (include/uapi/asm-generic/ioctl.h), matching
// hf/nsm's ioc package.
const (
	iocNRBits    = 8
	iocTypeBits  = 8
	iocSizeBits  = 14
	iocNRShift   = 0
	iocTypeShift = iocNRShift + iocNRBits
	iocSizeShift = iocTypeShift + iocTypeBits
	iocDirShift  = iocSizeShift + iocSizeBits
	iocWrite     = 1
	iocRead      = 2
)

func iocCommand(dir, typ, nr, size uintptr) uintptr {
	return (dir << iocDirShift) | (typ << iocTypeShift) | (nr << iocNRShift) | (size << iocSizeShift)
}

// nsmMessage mirrors the C `struct nsm_message { struct iovec request; struct
// iovec response; }`. syscall.Iovec is the platform iovec (Base *byte; Len), so
// the layout matches the driver's expectation exactly.
type nsmMessage struct {
	Request  syscall.Iovec
	Response syscall.Iovec
}

// nsmAttest issues an Attestation request to the NSM device over /dev/nsm and
// returns the raw COSE_Sign1 attestation document. f must be an open handle to
// /dev/nsm; nonce is embedded as the request's challenge so the document binds
// this run natively.
func nsmAttest(f *os.File, nonce []byte) ([]byte, error) {
	// Build the CBOR request the NSM driver expects: a single-key map whose value
	// is the Attestation parameters. nil user_data/public_key encode as CBOR null,
	// matching aws-nitro-enclaves-nsm-api's serde representation.
	req := map[string]any{
		"Attestation": map[string]any{
			"user_data":  nil,
			"nonce":      nonce,
			"public_key": nil,
		},
	}
	reqBytes, err := cbor.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal nsm request: %w", err)
	}

	resBuf := make([]byte, maxNSMResponse)

	var iovReq, iovRes syscall.Iovec
	iovReq.Base = &reqBytes[0]
	iovReq.SetLen(len(reqBytes))
	iovRes.Base = &resBuf[0]
	iovRes.SetLen(len(resBuf))

	msg := nsmMessage{Request: iovReq, Response: iovRes}

	cmd := iocCommand(iocRead|iocWrite, nsmIoctlMagic, 0, unsafe.Sizeof(msg))

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		cmd,
		uintptr(unsafe.Pointer(&msg)),
	)
	// Keep the buffers and msg alive across the syscall: the driver dereferences
	// the iovec Base pointers, and the GC must not move/collect them.
	runtime.KeepAlive(reqBytes)
	runtime.KeepAlive(resBuf)
	runtime.KeepAlive(&msg)
	if errno != 0 {
		return nil, fmt.Errorf("nsm ioctl on /dev/nsm failed: %w", errno)
	}

	// The driver updates the response iovec length to the bytes it wrote.
	n := msg.Response.Len
	if n == 0 || n > uint64(len(resBuf)) {
		return nil, fmt.Errorf("nsm ioctl returned implausible response length %d", n)
	}
	resCBOR := resBuf[:n]

	// Decode {"Attestation": {"document": <COSE_Sign1 bytes>}} and return the
	// document. An error response (e.g. {"Error": "..."}) yields no document.
	var resp struct {
		Attestation *struct {
			Document []byte `cbor:"document"`
		} `cbor:"Attestation"`
		Error string `cbor:"Error"`
	}
	if err := cbor.Unmarshal(resCBOR, &resp); err != nil {
		return nil, fmt.Errorf("decode nsm response: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("nsm device returned error: %s", resp.Error)
	}
	if resp.Attestation == nil || len(resp.Attestation.Document) == 0 {
		return nil, fmt.Errorf("nsm response carried no attestation document")
	}
	return resp.Attestation.Document, nil
}
