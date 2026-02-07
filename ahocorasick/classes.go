package ahocorasick

import (
	"math"
)

type byteClassBuilder []bool

func (b byteClassBuilder) setRange(start, end byte) {
	if start > 0 {
		b[int(start)-1] = true
	}
	b[int(end)] = true
}

func (b byteClassBuilder) build() byteClasses {
	var classes byteClasses
	var class byte
	i := 0
	for {
		classes.bytes[byte(i)] = class
		if i >= 255 {
			break
		}
		if b[i] {
			if class+1 > math.MaxUint8 {
				panic("shit happens")
			}
			class += 1
		}
		i += 1
	}
	return classes
}

func newByteClassBuilder() byteClassBuilder {
	return make([]bool, 256)
}

type byteClasses struct {
	bytes [256]byte
}

func singletons() byteClasses {
	var bc byteClasses
	for i := range bc.bytes {
		bc.bytes[i] = byte(i)
	}
	return bc
}
