package utility_misc

import (
	"fmt"
	"strings"
)

func Print(words ...string) {
	fmt.Println(strings.Join(words, " "))
}
