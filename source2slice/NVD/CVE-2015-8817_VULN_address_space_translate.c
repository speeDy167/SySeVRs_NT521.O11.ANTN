MemoryRegion *address_space_translate(AddressSpace *as, hwaddr addr,
                                      hwaddr *xlat, hwaddr *plen,
                                      bool is_write)
{
    IOMMUTLBEntry iotlb;
    MemoryRegionSection *section;
    MemoryRegion *mr;
    hwaddr len = *plen;

    for (;;) {
        section = address_space_translate_internal(as->dispatch, addr, &addr, plen, true);
        mr = section->mr;

        if (!mr->iommu_ops) {
            break;
        }

        iotlb = mr->iommu_ops->translate(mr, addr);
        addr = ((iotlb.translated_addr & ~iotlb.addr_mask)
                | (addr & iotlb.addr_mask));
        len = MIN(len, (addr | iotlb.addr_mask) - addr + 1);
        if (!(iotlb.perm & (1 << is_write))) {
            mr = &io_mem_unassigned;
            break;
        }

        as = iotlb.target_as;
    }

    *plen = len;
    *xlat = addr;
    return mr;
}
