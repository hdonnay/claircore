package gobin

import (
	"bytes"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

var magic = []byte("\xff Go buildinf:") // go magic build header

// Exe is a helper for grubbing around in ELF and PE executables.
//
// This is based on how the `go version` command extracts information from
// binaries.
type exe struct {
	name string

	elf *elf.File

	pe     *pe.File
	peBase uint64

	bin   binary.ByteOrder
	ptrSz int
	ptr   func([]byte) uint64
}

func mkExe(n string, b []byte) (*exe, error) {
	e := exe{name: n}
	var err error
	switch {
	case bytes.HasPrefix(b, []byte("\x7fELF")):
		e.elf, err = elf.NewFile(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
	case bytes.HasPrefix(b, []byte("MZ")):
		e.pe, err = pe.NewFile(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported executable format")
	}
	return &e, nil
}

// Info extracts the version and mod information from a binary or reports an
// error.
func (e *exe) Info() (ver string, mod [][]string, err error) {
	h, err := e.header()
	if err != nil {
		return "", nil, err
	}
	var m string
	ver, m, err = e.readHeader(h)
	if err != nil {
		return "", nil, err
	}

	if len(m) < 33 || m[len(m)-17] != '\n' {
		return ver, nil, nil
	}

	m = m[16 : len(m)-16]
	ls := strings.Split(m, "\n")
	for _, l := range ls {
		mod = append(mod, strings.Split(l, "\t"))
	}
	return ver, mod, nil
}

func (e *exe) header() ([]byte, error) {
	var rd io.Reader
Find:
	switch {
	case e.elf != nil:
		// New toolchains seem to embed the buildinfo in a dedicated section.
		if s := e.elf.Section(".go.buildinfo"); s != nil {
			rd = s.Open()
			break
		}
		// Older toolchains seem to just drop it in the data section.
		for _, p := range e.elf.Progs {
			if p.Type == elf.PT_LOAD && p.Flags&(elf.PF_X|elf.PF_W) == elf.PF_W {
				rd = p.Open()
				break Find
			}
		}
	case e.pe != nil:
		if e.peBase == 0 {
			switch oh := e.pe.OptionalHeader.(type) {
			case *pe.OptionalHeader32:
				e.peBase = uint64(oh.ImageBase)
			case *pe.OptionalHeader64:
				e.peBase = oh.ImageBase
			}
		}
		// Assume data is first writable section.
		const (
			IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
			IMAGE_SCN_MEM_READ             = 0x40000000
			IMAGE_SCN_MEM_WRITE            = 0x80000000
			IMAGE_SCN_ALIGN_32BYTES        = 0x600000
		)
		for _, s := range e.pe.Sections {
			if s.VirtualAddress != 0 &&
				s.Size != 0 &&
				s.Characteristics&^IMAGE_SCN_ALIGN_32BYTES == IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE {
				rd = s.Open()
				break Find
			}
		}
	default:
		panic("didn't use constructor")
	}
	b := make([]byte, 32)
	_, err := io.ReadFull(rd, b)
	for err == nil {
		if bytes.HasPrefix(b, magic) {
			return b, nil
		}
		_, err = io.ReadFull(rd, b)
	}
	return nil, errors.New("unable to find buildinfo")
}

func (e *exe) readAddr(addr uint64, b []byte) (int, error) {
	switch {
	case e.elf != nil:
		for _, p := range e.elf.Progs {
			if p.Vaddr <= addr && addr <= p.Vaddr+p.Filesz-1 {
				return p.ReadAt(b, int64(addr-p.Vaddr))
			}
		}
	case e.pe != nil:
		addr -= e.peBase
		for _, s := range e.pe.Sections {
			if uint64(s.VirtualAddress) <= addr && addr <= uint64(s.VirtualAddress+s.Size-1) {
				return s.ReadAt(b, int64(addr-uint64(s.VirtualAddress)))
			}
		}
	default:
		panic("didn't use constructor")
	}
	return -1, errors.New("address not mapped")
}

func (e *exe) readHeader(h []byte) (ver, mod string, err error) {
	e.ptrSz = int(h[14])
	e.bin = binary.LittleEndian
	if h[15] != 0 {
		e.bin = binary.BigEndian
	}
	e.ptr = e.bin.Uint64
	if e.ptrSz == 4 {
		e.ptr = func(b []byte) uint64 {
			return uint64(e.bin.Uint32(b))
		}
	}

	h = h[16:]
	ver, err = e.stringAt(h)
	if err != nil {
		return
	}
	mod, err = e.stringAt(h[e.ptrSz:])
	if err != nil {
		return
	}
	return
}

func (e *exe) stringAt(ea []byte) (string, error) {
	h := make([]byte, 2*e.ptrSz)
	n, err := e.readAddr(e.ptr(ea), h)
	if err != nil {
		return "", err
	}
	if n < len(h) {
		return "", errors.New("short read")
	}

	addr, sz := e.ptr(h), e.ptr(h[e.ptrSz:])

	out := make([]byte, sz)
	n, err = e.readAddr(addr, out)
	if err != nil {
		return "", err
	}
	if n < len(out) {
		return "", errors.New("short read")
	}

	return string(out), nil
}
