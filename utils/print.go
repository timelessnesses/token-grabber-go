package Python_Like_Printer

import (
	"fmt"
	"strings"
)

func Print(words ...string) {
	fmt.Println(strings.Join(words, " "))
}
