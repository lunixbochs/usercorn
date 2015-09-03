def fp_head(fp, n=4):
    c = fp.tell()
    head = fp.read(n).encode('hex')
    fp.seek(c)
    return head
