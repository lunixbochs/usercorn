package lua

import (
	"fmt"
	"github.com/lunixbochs/luaish"
	"strings"
)

func strslen(strs []string) int {
	i := 0
	for _, v := range strs {
		i += len(v)
	}
	return i
}

func (L *LuaRepl) prettydump(lv []lua.LValue, implicit bool, outer bool, seen map[lua.LValue]bool) []string {
	pretty := make([]string, len(lv))
	for i, v := range lv {
		switch s := v.(type) {
		case *lua.LTable:
			// seen[v] is used to skip recursive table references
			if _, ok := seen[v]; ok {
				pretty[i] = "{\"<skipped recursion>\"]}"
				continue
			}
			seen[v] = true

			table := make([]string, 0, s.Len())
			idx := 1
			s.ForEach(func(k, v lua.LValue) {
				tmp := L.prettydump([]lua.LValue{k, v}, implicit, false, seen)
				if n, ok := k.(lua.LInt); ok && int(n) == idx {
					idx += 1
					table = append(table, tmp[1])
				} else {
					table = append(table, strings.Join(tmp, " = "))
				}
			})

			seen[v] = false
			if outer {
				pretty[i] = "{" + strings.Join(table, ",\n ") + "}"
			} else {
				pretty[i] = "{" + strings.Join(table, ", ") + "}"
			}
		case lua.LFloat:
			pretty[i] = fmt.Sprintf("%f", float64(s))
		case lua.LInt:
			n := uint64(s)
			if n < 10 {
				pretty[i] = fmt.Sprintf("%d", n)
			} else if n > 0x10000 {
				pretty[i] = fmt.Sprintf("%#x", n)
			} else {
				pretty[i] = fmt.Sprintf("%#x(%d)", n, n)
			}
		case lua.LString:
			// for some reason repr doesn't print out null bytes properly
			// pretty[i] = models.Repr([]byte(s), 0)
			if implicit {
				pretty[i] = fmt.Sprintf("%#v", s)
			} else {
				pretty[i] = string(s)
			}
		default:
			pretty[i] = fmt.Sprintf("%s", s)
		}
	}
	return pretty
}

func (L *LuaRepl) PrettyDump(lv []lua.LValue, implicit bool, outer bool) []string {
	return L.prettydump(lv, implicit, outer, make(map[lua.LValue]bool))
}

func (L *LuaRepl) PrettyPrint(lv []lua.LValue, implicit bool) {
	pretty := L.PrettyDump(lv, implicit, true)
	L.Printf("%s\n", strings.Join(pretty, " "))
}
