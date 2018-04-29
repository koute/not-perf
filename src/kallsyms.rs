use std::cmp::max;
use range_map::RangeMap;

#[derive(Debug)]
pub struct KernelSymbol {
    pub address: u64,
    pub name: String,
    pub module: Option< String >
}

pub fn parse( kallsyms: &[u8] ) -> RangeMap< KernelSymbol > {
    let kallsyms = String::from_utf8_lossy( kallsyms );
    let mut symbols = Vec::new();
    let mut max_address = 0;
    for line in kallsyms.lines() {
        let line = line.trim();
        let mut iter = line.split_whitespace();
        let address = iter.next().unwrap();
        let address: u64 = if address == "(null)" {
            0
        } else {
            u64::from_str_radix( address, 16 ).unwrap()
        };
        let kind = iter.next().unwrap().as_bytes()[0];

        if kind != b't' && kind != b'T' {
            // To check which letter corresponds to what see `man nm`.
            continue;
        }

        let name = iter.next().unwrap();
        let module = iter.next().map( |module_s| {
            let rest = &line[ module_s.as_ptr() as usize - line.as_ptr() as usize.. ];
            let rest = rest.trim();
            &rest[ 1..rest.len() - 1 ]
        });

        max_address = max( max_address, address );
        let symbol = KernelSymbol {
            address,
            name: name.to_string(),
            module: module.map( |module_name| module_name.to_string() )
        };

        symbols.push( symbol );
    }

    symbols.sort_by_key( |symbol| symbol.address );

    let mut syms = Vec::with_capacity( symbols.len() );
    let mut iter = symbols.into_iter().peekable();
    while let Some( symbol ) = iter.next() {
        let start = symbol.address;
        let end = if let Some( next_symbol ) = iter.peek() {
            next_symbol.address
        } else {
            max_address
        };

        syms.push( ((start..end), symbol) );
    }

    debug!( "Loaded {} kernel symbols", syms.len() );
    RangeMap::from_vec( syms )
}
