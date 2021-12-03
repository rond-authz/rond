package utils

func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func AppendUnique(element *[]string, elementToAppend string) {
	if !Contains((*element), elementToAppend) {
		(*element) = append((*element), elementToAppend)
	}
}
