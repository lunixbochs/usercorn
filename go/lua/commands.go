package lua

var cmdRc = `
func _fallback(name, val)
    if type(val) == 'function' then
        val()
    else
        print val
    end
end

func _is_public(name)
    return _builtins[name] != true and name:sub(1, 1) != '_'
end

func help()
    local funcs = {}
    local vars = {}
    local vkeys = {}
    for name, val in pairs(_G) do
        if _is_public(name) then
            if type(val) == 'function' then
                table.insert(funcs, name)
            else
                vars[name] = val
                table.insert(vkeys, name)
            end
        end
    end
    table.sort(funcs)
    print 'Functions:'
    for _, name in ipairs(funcs) do
        print(name)
    end
    print

    table.sort(vkeys)
    print 'Variables:'
    for _, name in ipairs(vkeys) do
        local val = vars[name]
        print name '=' val
    end
end

func dir()
    local ret = {}
    for name, _ in pairs(_G) do
        if _is_public(name) then
            table.insert(ret, name)
        end
    end
    table.sort(ret)
    return ret
end

local _hook_types = {
    -- TODO: hook memory map?
    -- sys and sys_pre are hardcoded to call hook_sys
    code = cpu.HOOK_CODE,
    block = cpu.HOOK_BLOCK,
    intr = cpu.HOOK_INTR,
    read = cpu.HOOK_MEM_READ,
    write = cpu.HOOK_MEM_WRITE,
    fault = cpu.HOOK_MEM_ERR,
}

func _on_hook(name, fn, start, stop)
    if name == 'sys_pre' then
        return u.hook_sys_add(start, fn, nil)
    end
    if name == 'sys' then
        return u.hook_sys_add(start, nil, fn)
    end
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
        u.hook_sys_del(hh)
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

func maps(addr)
    print 'Memory map:'
    local m = us:Mappings()
    for i in m() do
        local map = m[i]
        if addr != nil then
            if map:Contains(addr) then
                print map:String()
                print '%#x: %#x+%#x' % {addr, map.Addr, addr-map.Addr}
                return
            end
        else
            print map:String()
        end
    end
    if addr != nil then
        print '%#x not found.' % addr
    end
end

func malloc(size, desc)
	if desc == nil then desc = "[script]" end
	addr, err = us:Malloc(size, desc)
	if err != nil then
		print err
	else
		return addr
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

func unmap(addr, size)
	u.mem_unmap(addr, size)
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

func rwto(insto)
    repeat
        rw 1
    until ins.name == insto
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

func regs(name)
    reglist, err = us:RegDump()
    for _, reg in reglist() do
        print reg.Name reg.Val
    end
end
r = regs
`
