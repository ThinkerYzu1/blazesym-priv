//! Parser of GSYM format.
//!
//! The layout of a standalone GSYM contains following sections in the order.
//!
//! * Header
//! * Address Table
//! * Address Data Offset Table
//! * File Table
//! * String Table
//! * Address Data
//!
//! The standalone GSYM starts with a Header, which describes the
//! size of an entry in the address table, the number of entries in
//! the address table, and the location and the size of the string
//! table.
//!
//! Since the Address Table is immediately after the Header, the
//! Header describes only the size of an entry and number of entries
//! in the table but not where it is.  The Address Table comprises
//! addresses of symbols in the ascending order, so we can find the
//! symbol an address belonging to by doing a binary search to find
//! the most close address but smaller or equal.
//!
//! The Address Data Offset Table has the same number of entries as
//! the Address Table.  Every entry in one table will has
//! corresponding entry at the same offset in the other table.  The
//! entries in the Address Data Offset Table are always 32bits
//! (4bytes.)  It is the file offset to the respective Address
//! Data. (AddressInfo actually)
//!
//! An AddressInfo comprises the size and name of a symbol.  The name
//! is an offset in the string table.  You will find a null terminated
//! C string at the give offset.  The size is the number of bytes of
//! the respective object; ex, a function or variable.
//!
//! See <https://reviews.llvm.org/D53379>
use super::types::*;

use std::io::{Error, ErrorKind};

use crate::tools::{decode_leb128, decode_leb128_s, decode_udword, decode_uhalf, decode_uword};
use std::ffi::CStr;

/// Hold the major parts of a standalone GSYM file.
///
/// GsymContext provides functions to access major entities in GSYM.
/// GsymContext can find respective AddressInfo for an address.  But,
/// it doesn't parse AddressData to get line numbers.
///
/// The developers should use [`parse_address_data()`],
/// [`parse_line_table_header()`], and [`linetab::run_op()`] to get
/// line number information from [`AddressInfo`].
pub struct GsymContext<'a> {
    header: Header,
    addr_tab: &'a [u8],
    addr_data_off_tab: &'a [u8],
    file_tab: &'a [u8],
    str_tab: &'a [u8],
    raw_data: &'a [u8],
}

impl<'a> GsymContext<'a> {
    /// Parse the Header of a standalone GSYM file.
    ///
    /// # Arguments
    ///
    /// * `data` - is the content of a standalone GSYM.
    ///
    /// Returns a GsymContext, which includes the Header and other important tables.
    pub fn parse_header(data: &[u8]) -> Result<GsymContext, Error> {
        let mut off = 0;
        // Parse Header
        let magic = decode_uword(data);
        if magic != GSYM_MAGIC {
            return Err(Error::new(ErrorKind::InvalidData, "invalid magic number"));
        }
        off += 4;
        let version = decode_uhalf(&data[off..]);
        if version != GSYM_VERSION {
            return Err(Error::new(ErrorKind::InvalidData, "unknown version number"));
        }
        off += 2;
        let addr_off_size = data[off];
        off += 1;
        let uuid_size = data[off];
        off += 1;
        let base_address = decode_udword(&data[off..]);
        off += 8;
        let num_addrs = decode_uword(&data[off..]);
        off += 4;
        let strtab_offset = decode_uword(&data[off..]);
        off += 4;
        let strtab_size = decode_uword(&data[off..]);
        off += 4;
        let uuid: [u8; 20] = (&data[off..(off + 20)])
            .try_into()
            .expect("input data is too short");
        off += 20;

        // Get the slices of the Address Table, Address Data Offset Table,
        // and String table.
        let end_off = off + num_addrs as usize * addr_off_size as usize;
        if end_off > data.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "the size of the file is smaller than expectation (address table)",
            ));
        }
        let addr_tab = &data[off..end_off];
        off = (end_off + 0x3) & !0x3;
        let end_off = off + num_addrs as usize * 4;
        if end_off > data.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "the size of the file is smaller than expectation (address data offset table)",
            ));
        }
        let addr_data_off_tab = &data[off..end_off];
        off += num_addrs as usize * 4;
        let file_num = decode_uword(&data[off..]);
        off += 4;
        let end_off = off + file_num as usize * 8;
        if end_off > data.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "the size of the file is smaller than expectation (file table)",
            ));
        }
        let file_tab = &data[off..end_off];
        let end_off = strtab_offset as usize + strtab_size as usize;
        if end_off > data.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "the size of the file is smaller than expectation (string table)",
            ));
        }
        let str_tab = &data[strtab_offset as usize..end_off];

        Ok(GsymContext {
            header: Header {
                magic,
                version,
                addr_off_size,
                uuid_size,
                base_address,
                num_addrs,
                strtab_offset,
                strtab_size,
                uuid,
            },
            addr_tab,
            addr_data_off_tab,
            file_tab,
            str_tab,
            raw_data: data,
        })
    }

    pub fn num_addresses(&self) -> usize {
        self.header.num_addrs as usize
    }

    /// Get the address of the an entry in the Address Table.
    ///
    /// # Saftety
    ///
    /// The code will crash with an invalid index.
    pub fn addr_at(&self, idx: usize) -> u64 {
        assert!(idx < self.header.num_addrs as usize, "invalid index");
        let off = idx * self.header.addr_off_size as usize;
        let mut addr = 0u64;
        let mut shift = 0;
        for d in &self.addr_tab[off..(off + self.header.addr_off_size as usize)] {
            addr |= (*d as u64) << shift;
            shift += 8;
        }
        addr += self.header.base_address;
        addr
    }

    /// Get the AddressInfo of an address given by an index.
    ///
    /// # Saftety
    ///
    /// The code will crash with an invalid index.
    pub fn addr_info(&self, idx: usize) -> AddressInfo {
        assert!(idx < self.header.num_addrs as usize, "invalid index");
        let off = idx * 4;
        let ad_off = decode_uword(&self.addr_data_off_tab[off..]) as usize;
        let size = decode_uword(&self.raw_data[ad_off..]);
        let name = decode_uword(&self.raw_data[ad_off + 4..]);
        AddressInfo {
            size,
            name,
            data: &self.raw_data[ad_off + 8..],
        }
    }

    /// Get the string at the given offset from the String Table.
    ///
    /// # Saftety
    ///
    /// The code will crash with an invalid offset.
    pub fn get_str(&self, off: usize) -> &str {
        assert!(off < self.str_tab.len());

        // Ensure there is a null byte.
        let mut null_off = self.str_tab.len() - 1;
        while null_off > off && self.str_tab[null_off] != 0 {
            null_off -= 1;
        }
        if null_off == off {
            return "";
        }

        // SAFETY: the lifetime of `CStr` can live as long as `self`.
        // The returned reference can also live as long as `self`.
        // So, it is safe.
        unsafe {
            CStr::from_ptr(self.str_tab[off..].as_ptr() as *const i8)
                .to_str()
                .unwrap()
        }
    }

    #[inline]
    pub fn file_info(&self, idx: usize) -> FileInfo {
        assert!(idx < (self.file_tab.len() / 8));
        let mut off = idx * 8;
        let directory = decode_uword(&self.file_tab[off..(off + 4)]);
        off += 4;
        let filename = decode_uword(&self.file_tab[off..(off + 4)]);
        FileInfo {
            directory,
            filename,
        }
    }
}

/// Find the index of an entry in the address table most likely
/// containing the given address.
///
/// The callers should check the respective `AddressInfo` to make sure
/// it is what they request for.
pub fn find_address(ctx: &GsymContext, addr: u64) -> usize {
    let mut left = 0;
    let mut right = ctx.num_addresses();

    if right == 0 {
        return 0;
    }
    if addr < ctx.addr_at(0) {
        return 0;
    }

    while (left + 1) < right {
        let v = (left + right) / 2;
        let cur_addr = ctx.addr_at(v);

        if addr == cur_addr {
            return v;
        }
        if addr < cur_addr {
            right = v;
        } else {
            left = v;
        }
    }
    left
}

/// Parse AddressData.
///
/// AddressDatas are items following AndressInfo.
/// [`GsymContext::addr_info()`] returns the raw data of AddressDatas as a
/// slice at [`AddressInfo::data`].
///
/// # Arguments
///
/// * `data` - is the slice from AddressInfo::data.
///
/// Returns a vector of [`AddressData`].
pub fn parse_address_data(data: &[u8]) -> Vec<AddressData> {
    let mut data_objs = vec![];

    let mut off = 0;
    while off < data.len() {
        let typ = decode_uword(&data[off..]);
        off += 4;
        let length = decode_uword(&data[off..]);
        off += 4;
        let d = &data[off..(off + length as usize)];
        data_objs.push(AddressData {
            typ,
            length,
            data: d,
        });
        off += length as usize;

        #[allow(non_upper_case_globals)]
        match typ {
            InfoTypeEndOfList => {
                break;
            }
            InfoTypeLineTableInfo | InfoTypeInlineInfo => {}
            _ => {
                #[cfg(debug_assertions)]
                eprintln!("unknown info type");
            }
        }
    }

    data_objs
}

/// Parse AddressData of InfoTypeLineTableInfo.
///
/// An `AddressData` of `InfoTypeLineTableInfo` type is a table of
/// line numbers for a symbol.  AddressData is the payload of
/// `AddressInfo`.  One AddressInfo may have several AddressData
/// entries in its payload.  Each AddressData entry stores a type of
/// data relates to the symbol the `AddressInfo` presents.
///
/// # Arguments
///
/// * `data` - is what [`AddressData::data`] is.
///
/// Return the `LineTableHeader` and the size of the header of a
/// `AddressData` entry of InfoTypeLineTableInfo type in the payload
/// of an `Addressinfo`.
pub fn parse_line_table_header(data: &[u8]) -> Result<(LineTableHeader, usize), Error> {
    let mut off = 0;
    let (min_delta, bytes) = decode_leb128_s(&data[off..])
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "can not parse a leb128"))?;
    off += bytes as usize;
    let (max_delta, bytes) = decode_leb128_s(&data[off..])
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "can not parse a leb128"))?;
    off += bytes as usize;
    let (first_line, bytes) = decode_leb128(&data[off..])
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "can not parse an unsigned leb128"))?;
    off += bytes as usize;
    Ok((
        LineTableHeader {
            min_delta,
            max_delta,
            first_line: first_line as u32,
        },
        off,
    ))
}

/// InlineInfoContext maintains the states to travel the tree of inline information.
///
/// The inline information of GSYM is represented as a tree of address
/// ranges.  The range of a parent InlineInfo will cover every ranges
/// of children.  This type tries to find the InlineInfo with the
/// fittest range.  The InlineInfos along the path from the root to
/// the fittest one are the functions inlined.
pub struct InlineInfoContext<'a> {
    data: &'a [u8],
    offset: usize,
    inline_stack: Vec<InlineInfo>,
    address: u64,
}

impl<'a> InlineInfoContext<'a> {
    pub fn new(data: &[u8], address: u64) -> InlineInfoContext {
        InlineInfoContext {
            data,
            offset: 0,
            inline_stack: vec![],
            address,
        }
    }

    /// Parse one InlineInfo.
    fn parse_one(data: &[u8]) -> Result<(InlineInfo, usize), Error> {
        let (num_ranges, bytes) = decode_leb128(data)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "can not parse num_ranges"))?;
        let mut off = bytes as usize;

        if num_ranges == 0 {
            // Empty InlineInfo
            return Ok((
                InlineInfo {
                    ranges: vec![],
                    name: 0,
                    has_children: false,
                    call_file: 0,
                    call_line: 0,
                },
                off,
            ));
        }

        let mut ranges = vec![];
        for _ in 0..num_ranges {
            let (addr_offset, bytes) = decode_leb128(&data[off..])
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "can not parse addr_offset"))?;
            off += bytes as usize;
            let (size, bytes) = decode_leb128(&data[off..])
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "can not parse size"))?;
            off += bytes as usize;
            ranges.push(OffsetRange { addr_offset, size });
        }

        if off >= data.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "can not parse has_children",
            ));
        }
        let has_children = data[off] > 0;
        off += 1;

        if (off + 4) > data.len() {
            return Err(Error::new(ErrorKind::InvalidData, "can not parse name"));
        }
        let name = decode_uword(&data[off..]);
        off += 4;

        let (call_file, bytes) = decode_leb128(&data[off..])
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "can not parse call_file"))?;
        off += bytes as usize;
        let (call_line, bytes) = decode_leb128(&data[off..])
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "can not parse call_line"))?;
        off += bytes as usize;

        Ok((
            InlineInfo {
                ranges,
                name,
                has_children,
                call_file,
                call_line,
            },
            off,
        ))
    }

    #[inline]
    fn is_done(&self) -> bool {
        self.inline_stack.is_empty() && self.offset == self.data.len()
    }

    /// Parse one InlineInfo from the `data` and maintain the `inline_stack`.
    ///
    /// `inline_stack` stores `InlineInfo`s of all inline callers.
    fn step(&mut self) -> Result<(), Error> {
        if !self.inline_stack.is_empty() && self.top().ranges.is_empty() {
            // If ranges is empty, it is an empty InlineInfo and the
            // last one of its siblings.
            self.inline_stack.pop().unwrap(); // pop empty one
            self.inline_stack.pop().unwrap(); // pop parent
        }

        if self.is_done() {
            // Complete the whole inline informatin.
            return Ok(());
        }

        if self.inline_stack.is_empty() && self.offset > 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "garbage data at the tail",
            ));
        }

        let (info, bytes) = InlineInfoContext::parse_one(&self.data[self.offset..])?;
        self.offset += bytes;
        if self.inline_stack.is_empty() || self.top().has_children {
            self.inline_stack.push(info);
        } else {
            let stk_len = self.inline_stack.len();
            self.inline_stack[stk_len - 1] = info;
        }
        Ok(())
    }

    /// Skip all children until find the next sibling.
    ///
    /// It doesn't move if the current InlineInfo is the last one of
    /// its siblings.
    fn skip_to_sibling(&mut self) -> Result<(), Error> {
        if self.inline_stack.is_empty() || self.top().ranges.is_empty() {
            return Ok(());
        }
        let depth = self.inline_stack.len();
        self.step()?;
        while self.inline_stack.len() != depth {
            self.step()?;
        }
        Ok(())
    }

    /// The start address of ranges are offsets from the first range
    /// of the parent InlineInfo.  We need to recover its values by
    /// adding offsets of InlineInfo on the inline stack together.
    fn top_ranges(&self) -> Vec<(u64, u64)> {
        let mut addr = self.address;
        if self.inline_stack.len() > 1 {
            for info in &self.inline_stack[0..self.inline_stack.len() - 1] {
                addr += info.ranges[0].addr_offset;
            }
        }
        self.inline_stack[self.inline_stack.len() - 1]
            .ranges
            .iter()
            .map(|x| (x.addr_offset + addr, x.size))
            .collect()
    }

    #[inline]
    fn top(&self) -> &InlineInfo {
        &self.inline_stack[self.inline_stack.len() - 1]
    }

    /// Seek to the most inner InlineInfo.
    ///
    /// The context will stop at an address range that covers the
    /// given `addr` if there is.  [`get_inline_stack()`] will returns
    /// all inlined functions in the range.
    pub fn seek_address(&mut self, addr: u64) -> Result<(), Error> {
        self.step()?;
        while !self.is_done() {
            if !self.top().has_children {
                // The last sibling.
                break;
            }

            if self.top().ranges.is_empty() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "An empty InlineInfo should not have children",
                ));
            }

            if !self
                .top_ranges()
                .iter()
                .any(|(start, size)| addr >= *start && addr < (*start + *size))
            {
                self.skip_to_sibling()?;
                continue;
            }

            self.step()?;
        }

        if self.inline_stack.is_empty()
            || self.inline_stack.len() == 1 && self.top().ranges.is_empty()
        {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "even most outer inline fucntion doesn't match",
            ));
        }

        Ok(())
    }

    /// Get a list of inlined functions at the visiting range of addresses.
    #[inline]
    pub fn get_inline_stack(&self) -> &[InlineInfo] {
        if self.inline_stack.len() == 1 && self.top().ranges.is_empty() {
            &self.inline_stack[0..self.inline_stack.len() - 1]
        } else {
            &self.inline_stack
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::linetab::{run_op, RunResult};
    use super::super::types::*;
    use super::*;
    use std::env;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::path::Path;

    #[test]
    fn test_parse_context() {
        let args: Vec<String> = env::args().collect();
        let bin_name = &args[0];
        let test_gsym = Path::new(bin_name)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("data")
            .join("test.gsym");
        let mut gsym_fo = File::open(test_gsym).unwrap();
        let mut data = vec![];

        gsym_fo.read_to_end(&mut data).unwrap();
        let ctx = GsymContext::parse_header(&data).unwrap();

        let idx = 2;
        // Check gsym-example.c for these hard-coded addresses
        assert_eq!(ctx.addr_at(idx), 0x0000000002020000);
        let addrinfo = ctx.addr_info(idx);
        assert_eq!(ctx.get_str(addrinfo.name as usize), "factorial");

        let idx = find_address(&ctx, 0x0000000002000000);
        assert_eq!(idx, 0);
        let addrinfo = ctx.addr_info(idx);
        assert_eq!(ctx.get_str(addrinfo.name as usize), "main");

        let addrdata_objs = parse_address_data(addrinfo.data);
        assert_eq!(addrdata_objs.len(), 3);
        let mut line_info_cnt = 0;
        for o in addrdata_objs {
            if o.typ == InfoTypeLineTableInfo {
                let hdr = parse_line_table_header(o.data);
                if let Ok((hdr, bytes)) = hdr {
                    let mut ltctx = LineTableRow {
                        address: 0x0000000002000000,
                        file_idx: 1,
                        file_line: hdr.first_line,
                    };
                    let ops = &o.data[bytes..];
                    let mut pc = 0;
                    let mut addrs = vec![];
                    let mut lines = vec![];
                    while pc < ops.len() {
                        match run_op(&mut ltctx, &hdr, ops, pc) {
                            RunResult::Ok(bytes) => {
                                pc += bytes;
                            }
                            RunResult::NewRow(bytes) => {
                                let finfo = ctx.file_info(ltctx.file_idx as usize);
                                let filename = ctx.get_str(finfo.filename as usize);
                                assert_eq!(filename, "gsym-example.c");
                                addrs.push(ltctx.address);
                                lines.push(ltctx.file_line);
                                pc += bytes;
                            }
                            RunResult::Err => {
                                break;
                            }
                            RunResult::End => {
                                break;
                            }
                        }
                    }

                    assert_eq!(
                        addrs,
                        [
                            0x0000000002000000,
                            0x0000000002000001,
                            0x0000000002000001,
                            0x0000000002000001,
                            0x0000000002000001,
                            0x000000000200000b,
                            0x0000000002000010,
                            0x0000000002000017,
                            0x000000000200001f,
                            0x000000000200001f
                        ]
                    );
                    assert_eq!(lines, [53, 54, 56, 48, 49, 57, 58, 57, 60, 61]);
                    line_info_cnt += 1;
                }
            }
        }
        assert_eq!(line_info_cnt, 1);
    }

    #[test]
    fn test_parse_inline() {
        let args: Vec<String> = env::args().collect();
        let bin_name = &args[0];
        let test_gsym = Path::new(bin_name)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("data")
            .join("test.gsym");
        let mut gsym_fo = File::open(test_gsym).unwrap();
        let mut data = vec![];

        gsym_fo.read_to_end(&mut data).unwrap();
        let ctx = GsymContext::parse_header(&data).unwrap();

        let tgt_addr = 0x0000000002000027;
        let idx = find_address(&ctx, tgt_addr);
        assert_eq!(ctx.addr_at(idx), 0x0000000002000026);
        let addrinfo = ctx.addr_info(idx);
        let name = ctx.get_str(addrinfo.name as usize);
        assert_eq!(name, "fibbonacci");

        let tgt_addr = 0x0000000002000003;
        let idx = find_address(&ctx, tgt_addr);
        assert_eq!(ctx.addr_at(idx), 0x0000000002000000);
        let addrinfo = ctx.addr_info(idx);
        let name = ctx.get_str(addrinfo.name as usize);
        assert_eq!(name, "main");

        let addrdata_objs = parse_address_data(addrinfo.data);
        assert_eq!(addrdata_objs.len(), 3);
        let mut inline_info_cnt = 0;
        for o in addrdata_objs {
            if o.typ == InfoTypeInlineInfo {
                inline_info_cnt += 1;
                let mut inlinectx = InlineInfoContext::new(o.data, ctx.addr_at(idx));
                inlinectx.seek_address(tgt_addr).unwrap();
                let mut stk = inlinectx.get_inline_stack().iter();

                let info = stk.next().unwrap();
                let name = ctx.get_str(info.name as usize);
                assert_eq!(name, "main");

                let info = stk.next().unwrap();
                let name = ctx.get_str(info.name as usize);
                assert_eq!(name, "factorial_inline_wrapper");

                let finfo = ctx.file_info(info.call_file as usize);
                let filename = ctx.get_str(finfo.filename as usize);
                assert_eq!(filename, "gsym-example.c");
                assert_eq!(info.call_line, 56);
            }
        }
        assert_eq!(inline_info_cnt, 1);
    }

    #[test]
    fn test_find_address() {
        let args: Vec<String> = env::args().collect();
        let bin_name = &args[0];
        let test_gsym = Path::new(bin_name)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("data")
            .join("test.gsym");
        let mut gsym_fo = File::open(test_gsym).unwrap();
        let mut data = vec![];

        const TEST_SIZE: usize = 6;

        gsym_fo.read_to_end(&mut data).unwrap();

        let mut addr_tab = Vec::<u8>::new();
        addr_tab.resize(TEST_SIZE * 4, 0);

        let mut values: Vec<u32> = (0_u32..(TEST_SIZE as u32)).into_iter().collect();

        let copy_to_addr_tab = |values: &[u32], addr_tab: &mut Vec<u8>| {
            addr_tab.clear();
            for v in values {
                let r = addr_tab.write(&v.to_ne_bytes());
                assert!(r.is_ok());
            }
        };
        // Generate all possible sequences that values are in strictly
        // ascending order and `< TEST_SIZE * 2`.
        let gen_values = |values: &mut [u32]| {
            let mut carry_out = TEST_SIZE as u32 * 2;
            for i in (0..values.len()).into_iter().rev() {
                values[i] += 1;
                if values[i] >= carry_out {
                    carry_out -= 1;
                    continue;
                }
                // Make all values at right side minimal and strictly
                // ascending.
                for j in (i + 1)..values.len() {
                    values[j] = values[j - 1] + 1;
                }
                break;
            }
        };

        while values[0] <= TEST_SIZE as u32 {
            copy_to_addr_tab(&values, &mut addr_tab);

            for addr in 0..(TEST_SIZE * 2) {
                let addr_tab = addr_tab.clone();
                let mut ctx = GsymContext::parse_header(&data).unwrap();
                ctx.header.num_addrs = TEST_SIZE as u32;
                ctx.header.addr_off_size = 4;
                ctx.header.base_address = 0;
                ctx.addr_tab = addr_tab.as_slice();

                let idx = find_address(&ctx, addr as u64);
                let addr_u32 = addr as u32;
                let idx1 = match values.binary_search(&addr_u32) {
                    Ok(idx) => idx,
                    Err(idx) => {
                        // When the searching value is falling in
                        // between two values, it will return the
                        // index of the later one. But we want the
                        // earlier one.
                        if idx > 0 {
                            idx - 1
                        } else {
                            0
                        }
                    }
                };
                assert_eq!(idx, idx1);
            }

            gen_values(&mut values);
        }
    }
}
