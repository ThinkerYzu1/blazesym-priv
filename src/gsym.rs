use std::fs::File;
use std::io::{Error, Read};
use std::mem;
use std::path::{Path, PathBuf};

use super::{AddressLineInfo, FindAddrOpts, InlineFunc, SymResolver, SymbolInfo};

mod linetab;
mod parser;
mod types;

use linetab::{line_table_row_from, run_op, RunResult};
use parser::{
    find_address, parse_address_data, parse_line_table_header, GsymContext, InlineInfoContext,
};
use types::{InfoTypeInlineInfo, InfoTypeLineTableInfo};

/// The symbol resolver for the GSYM format.
pub struct GsymResolver {
    file_name: PathBuf,
    ctx: GsymContext<'static>,
    #[allow(dead_code)]
    data: Vec<u8>,
    loaded_address: u64,
}

impl GsymResolver {
    pub fn new(file_name: PathBuf, loaded_address: u64) -> Result<GsymResolver, Error> {
        let mut fo = File::open(&file_name)?;
        let mut data = vec![];
        fo.read_to_end(&mut data)?;
        let ctx = GsymContext::parse_header(&data)?;

        Ok(GsymResolver {
            file_name,
            // SAFETY: the lifetime of ctx depends on data, which is
            // owned by the object.  So, it is safe to strip the
            // lifetime of ctx.
            ctx: unsafe { mem::transmute(ctx) },
            data,
            loaded_address,
        })
    }
}

impl SymResolver for GsymResolver {
    fn get_address_range(&self) -> (u64, u64) {
        let sz = self.ctx.num_addresses();
        if sz == 0 {
            return (0, 0);
        }

        let start = self.ctx.addr_at(0) + self.loaded_address;
        let end =
            self.ctx.addr_at(sz - 1) + self.ctx.addr_info(sz - 1).size as u64 + self.loaded_address;
        (start, end)
    }

    fn find_symbols(&self, addr: u64) -> Vec<(&str, u64)> {
        let addr = addr - self.loaded_address;
        let idx = find_address(&self.ctx, addr);
        let found = self.ctx.addr_at(idx);
        if addr < found {
            return vec![];
        }

        let info = self.ctx.addr_info(idx);
        let name = self.ctx.get_str(info.name as usize);
        vec![(name, found + self.loaded_address)]
    }

    fn find_address(&self, _name: &str, _opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        // It is inefficient to find the address of a symbol with
        // GSYM.  We may support it in the future if needed.
        None
    }

    fn find_address_regex(&self, _pattern: &str, _opts: &FindAddrOpts) -> Option<Vec<SymbolInfo>> {
        None
    }

    fn find_line_info(&self, addr: u64) -> Option<AddressLineInfo> {
        let addr = addr - self.loaded_address;
        let idx = find_address(&self.ctx, addr);
        let symaddr = self.ctx.addr_at(idx);
        if addr < symaddr {
            return None;
        }
        let addrinfo = self.ctx.addr_info(idx);
        if addr >= (symaddr + addrinfo.size as u64) {
            return None;
        }

        let addrdatas = parse_address_data(addrinfo.data);
        for addrdata in addrdatas {
            if addrdata.typ != InfoTypeLineTableInfo {
                continue;
            }
            let lthdr = parse_line_table_header(addrdata.data);
            if lthdr.is_err() {
                #[cfg(debug_assertions)]
                eprintln!("invalid line table header");
                return None;
            }
            let (lthdr, bytes) = lthdr.unwrap();
            let ops = &addrdata.data[bytes..];
            let mut ltr = line_table_row_from(&lthdr, symaddr);
            let mut saved_ltr = ltr.clone();
            let mut row_cnt = 0;
            let mut pc = 0;
            while pc < ops.len() {
                match run_op(&mut ltr, &lthdr, ops, pc) {
                    RunResult::Ok(bytes) => {
                        pc += bytes as usize;
                    }
                    RunResult::NewRow(bytes) => {
                        pc += bytes as usize;
                        row_cnt += 1;
                        if addr == ltr.address {
                            break;
                        }
                        if addr < ltr.address {
                            if row_cnt == 1 {
                                return None;
                            }
                            ltr = saved_ltr.clone();
                            break;
                        }
                        saved_ltr = ltr.clone();
                    }
                    RunResult::End | RunResult::Err => {
                        break;
                    }
                }
            }

            if row_cnt == 0 {
                continue;
            }

            let finfo = self.ctx.file_info(ltr.file_idx as usize);
            let dirname = self.ctx.get_str(finfo.directory as usize);
            let filename = self.ctx.get_str(finfo.filename as usize);
            let path = Path::new(dirname)
                .join(filename)
                .to_str()
                .unwrap()
                .to_string();
            return Some(AddressLineInfo {
                path,
                line_no: ltr.file_line as usize,
                column: 0,
            });
        }
        None
    }

    fn addr_file_off(&self, _addr: u64) -> Option<u64> {
        // Unavailable
        None
    }

    fn get_obj_file_name(&self) -> &Path {
        &self.file_name
    }

    fn find_inline_functions(&self, addr: u64) -> Option<Vec<InlineFunc>> {
        let addr = addr - self.loaded_address;
        let idx = find_address(&self.ctx, addr);
        let symaddr = self.ctx.addr_at(idx);
        if addr < symaddr {
            return None;
        }
        let addrinfo = self.ctx.addr_info(idx);
        if addr >= (symaddr + addrinfo.size as u64) {
            return None;
        }

        let addrdatas = parse_address_data(addrinfo.data);
        let addrdata = addrdatas
            .iter()
            .find(|addrdata| addrdata.typ == InfoTypeInlineInfo);
        if addrdata.is_none() {
            return Some(vec![]);
        }
        let addrdata = addrdata.unwrap();

        let mut inline_ctx = InlineInfoContext::new(addrdata.data, symaddr);
        inline_ctx.seek_address(addr).ok()?;

        let stk = inline_ctx.get_inline_stack().iter().map(|info| {
            let file_info = self.ctx.file_info(info.call_file as usize);
            let dir = self.ctx.get_str(file_info.directory as usize);
            let fname = self.ctx.get_str(file_info.filename as usize);
            let full_path = Path::new(dir).join(fname).to_str().unwrap().to_string();
            InlineFunc {
                name: self.ctx.get_str(info.name as usize).to_string(),
                file_name: full_path,
                line_no: info.call_line as usize,
            }
        });
        Some(stk.collect())
    }

    fn repr(&self) -> String {
        format!("GSYM {:?}", self.file_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_find_line_info() {
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
        let resolver = GsymResolver::new(test_gsym, 0).unwrap();

        let linfo = resolver.find_line_info(0x0000000002000001);
        assert!(linfo.is_some());
        let linfo = linfo.unwrap();
        assert_eq!(linfo.line_no, 54);
        assert!(linfo.path.ends_with("gsym-example.c"));
    }

    #[test]
    fn test_find_symbols() {
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
        let resolver = GsymResolver::new(test_gsym, 0).unwrap();

        let syms = resolver.find_symbols(0x0000000002020000);
        assert_eq!(syms.len(), 1);
        let (name, addr) = syms[0];
        assert_eq!(name, "factorial");
        assert_eq!(addr, 0x0000000002020000);
    }
}
