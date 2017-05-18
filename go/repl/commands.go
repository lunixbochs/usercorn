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

local _hook_types = {
	-- TODO: hook sys, map?
	code = cpu.HOOK_CODE,
	block = cpu.HOOK_BLOCK,
	intr = cpu.HOOK_INTR,
	read = cpu.HOOK_MEM_READ,
	write = cpu.HOOK_MEM_WRITE,
	fault = cpu.HOOK_MEM_ERR,
}

func _on_hook(name, fn, start, stop)
	local type = _hook_types[name]
	if type != nil then
		if start == nil then return u.hook_add(type, fn)
		else return u.hook_add(type, fn, start, stop) end
	end
	print 'unimplemented hook type %s' % name
    -- u.on_hook_add(name, fn, start, stop)
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
