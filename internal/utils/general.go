package utils

import "github.com/elliotchance/pie/pie"

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

func FilterList(list []string, valuesToFilter []string) []string {
	pieList := pie.Strings(list)
	newList := pieList.Filter(func(listItem string) bool {
		return !Contains(valuesToFilter, listItem)
	})
	return newList
}
