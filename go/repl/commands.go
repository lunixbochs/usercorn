package repl

var cmdRc = `
func _fallback(name, val)
    if type(val) == 'function' then
        val()
    else
        print val
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
		if start == nil then
			return u.hook_add(type, fn)
		else
			if stop == nil then stop = start end
			return u.hook_add(type, fn, start, stop)
		end
	end
	print 'unimplemented hook type %s' % name
    -- u.on_hook_add(name, fn, start, stop)
end

func off()
	if hh then
		u.hook_del(hh)
		hh = nil
	end
end

func read(addr, size)
	if size == nil then size = 16 end
	return u.mem_read(addr, size)
end

func write(addr, s)
	u.mem_write(addr, s)
end

func maps()
	print 'Memory map:'
	local m = us:Mappings()
	for i in m() do
	print m[i]:String()
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

func asm(src, addr)
	if addr == nil then addr = 0 end
	return u.asm(src, addr)
end

func patch(addr, src)
	local x = asm(src, addr)
	-- autonop
	local total = 0
	for _, ins in pairs(u.dis(addr, x:len() + 16)) do
		total = total + ins.bytes:len()
		if total == x:len() then break end
		if total > x:len() then
			x = x .. asm('nop', 0):rep(total - x:len())
			break
		end
	end
	write(addr, x)
end

func dis(addr, size, indent, count)
	if addr == nil then addr = pc end
	if size == nil then size = 16 end
	if indent == nil then indent = 0 end
	local pad = (' '):rep(indent)
	local d = u.dis(addr, size)
	local width = 0
	for i, ins in ipairs(d) do
		if count != nil and i > count then break end
		local fmt = pad .. '0x%x: %s %s'
		print fmt % {ins.addr, ins.name, ins.op_str}
	end
end


func s(steps)
	if steps == nil then steps = 1 end
	u.step(steps)
end

c = u.continue
func rewind(n)
	if n == nil then n = 1 end
	u.rewind_n(n)
end
rw = rewind
rwaddr = u.rewind_addr

func rwto(ins)
	while true do
		rw 1
	end
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

func runto(name)
    on code do
        if ins.name == name then
            print '[-] stopping at "%s"' % name
            dis pc 16 0 1
            u.stop()
            off
        end
    end
    c
end
`
