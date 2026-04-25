package e2e

import "os"

func osMkdirAll(p string) error            { return os.MkdirAll(p, 0o755) }
func osWriteFile(p string, b []byte) error { return os.WriteFile(p, b, 0o644) }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
