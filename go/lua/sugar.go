package lua

var sugarRc = `
getmetatable("").__mod = func(a, b)
    if type(b) == 'table' then
        return string.format(a, unpack(b))
    end
    return string.format(a, b)
end

func hex(s) return '%x' % s end
func ord(s) return string.byte(s, 1) end
func chr(s) return string.char(s) end

func range(a, b, c)
    local i, stop, step = 0, a, 1
    if b != nil then
        if c != nil then step = c end
        i, stop = a, b
    end
    i = i - 1
    return func()
        i = i + step
        if (step > 0 and i < stop) or (step < 0 and i > stop) then
            return i
        end
    end
end

func hexdump(s)
    print '%x' % s
end
`
