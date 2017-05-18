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
func maps()
	print 'Memory map:'
	local m = us:Mappings()
	for i in m() do
		print m[i]
	end
end
func map(addr, size, prot)
    if addr == nil then
		maps()
    else
        if prot == nil then prot = cpu.PROT_ALL end
        u.mem_map(addr, size, prot)
    end
end

func dis(addr, size)
	if addr == nil then addr = pc end
	if size == nil then size = 16 end
	print us:Dis(addr, size, true)
end

func c() us:Gate():UnlockStopRelock() end

func s(steps)
	if steps == nil then steps = 1 end
	local i = 0
	local hh = 0
	hh = u.hook_add(cpu.HOOK_CODE, func()
		i = i + 1
		if i == steps + 1 then
			u.stop()
		end
	end, 1, 0)
	us:Gate():UnlockStopRelock()
	u.hook_del(hh)
end

func b(baddr)
	local hh = u.hook_add(cpu.HOOK_CODE, func()
		if bskip == baddr then
			bskip = nil
			return
		end
		bskip = baddr
		print 'Breakpoint N hit at 0x%x' % baddr
		u.stop()
	end, baddr, baddr)
	print 'Breakpoint N at 0x%x' % baddr
end
`
