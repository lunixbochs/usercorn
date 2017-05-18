package repl

var cmdRc = `
func _fallback(a)
    if type(a) == 'function' then
        a()
    else
        -- TODO: send this to some kind of repl printer instead
        print a
    end
end

func _on_hook(name, fn, start, stop)
    u.on_hook_add(name, fn, start, stop)
end

func read(addr, size) return u.mem_read(addr, size) end
func write(addr, s) u.mem_write(addr, size) end
func map(addr, size, prot)
    if addr == nil then
		print 'Memory map:'
		local m = us:Mappings()
		for i in m() do
			print m[i]
		end
    else
        if prot == nil then prot = cpu.PROT_ALL end
        u.mem_map(addr, size, prot)
    end
end
`
