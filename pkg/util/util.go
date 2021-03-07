package util

func SplitFunc(c rune) bool {
	return c == ' ' || c == '\n' || c == '\r'
}

func StrSliceContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
