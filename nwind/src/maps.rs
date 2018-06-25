use regex::Regex;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub is_read: bool,
    pub is_write: bool,
    pub is_executable: bool,
    pub is_shared: bool,
    pub file_offset: u64,
    pub major: u32,
    pub minor: u32,
    pub inode: u64,
    pub name: String
}

lazy_static! {
    static ref MAPS_REGEX: Regex = Regex::new( r"^([0-9a-f]+)-([0-9a-f]+) (.)(.)(.)(.) ([0-9a-f]+) (\S+):(\S+) (\d+)\s*(.*)" ).unwrap();
}

pub fn parse( maps: &str ) -> Vec< Region > {
    if maps.is_empty() {
        return Vec::new();
    }

    let mut output = Vec::new();
    let regex = &*MAPS_REGEX;
    for line in maps.trim().split( '\n' ) {
        let caps = match regex.captures( line ) {
            Some( caps ) => caps,
            None => {
                panic!( "Maps regex match failed for: {:?}", line );
            }
        };

        let start = u64::from_str_radix( caps.get(1).unwrap().as_str(), 16 ).unwrap();
        let end = u64::from_str_radix( caps.get(2).unwrap().as_str(), 16 ).unwrap();
        let is_read = caps.get(3).unwrap().as_str() == "r";
        let is_write = caps.get(4).unwrap().as_str() == "w";
        let is_executable = caps.get(5).unwrap().as_str() == "x";
        let is_shared = caps.get(6).unwrap().as_str() == "s";
        let file_offset = u64::from_str_radix( caps.get(7).unwrap().as_str(), 16 ).unwrap();
        let major = u32::from_str_radix( caps.get(8).unwrap().as_str(), 16 ).unwrap();
        let minor = u32::from_str_radix( caps.get(9).unwrap().as_str(), 16 ).unwrap();
        let inode = caps.get(10).unwrap().as_str().parse().unwrap();
        let name = caps.get(11).unwrap().as_str().to_owned();

        output.push( Region {
            start,
            end,
            is_read,
            is_write,
            is_executable,
            is_shared,
            file_offset,
            major,
            minor,
            inode,
            name
        });
    }

    output
}

#[test]
fn test_parse() {
    let maps = r#"
00400000-0040c000 r-xp 00000000 08:02 1321238                            /usr/bin/cat
0060d000-0062e000 rw-p 00000000 00:00 0                                  [heap]
7ffff672c000-7ffff69db000 r--s 00001ac2 1f:33 1335289                    /usr/lib/locale/locale-archive
7ffff5600000-7ffff5800000 rw-p 00000000 00:00 0
"#;

    assert_eq!(
        parse( maps ),
        vec![
            Region {
                start: 0x00400000,
                end: 0x0040c000,
                is_read: true,
                is_write: false,
                is_executable: true,
                is_shared: false,
                file_offset: 0,
                major: 0x08,
                minor: 0x02,
                inode: 1321238,
                name: "/usr/bin/cat".to_owned()
            },
            Region {
                start: 0x0060d000,
                end: 0x0062e000,
                is_read: true,
                is_write: true,
                is_executable: false,
                is_shared: false,
                file_offset: 0,
                major: 0,
                minor: 0,
                inode: 0,
                name: "[heap]".to_owned()
            },
            Region {
                start: 0x7ffff672c000,
                end: 0x7ffff69db000,
                is_read: true,
                is_write: false,
                is_executable: false,
                is_shared: true,
                file_offset: 0x1ac2,
                major: 0x1f,
                minor: 0x33,
                inode: 1335289,
                name: "/usr/lib/locale/locale-archive".to_owned()
            },
            Region {
                start: 0x7ffff5600000,
                end: 0x7ffff5800000,
                is_read: true,
                is_write: true,
                is_executable: false,
                is_shared: false,
                file_offset: 0,
                major: 0,
                minor: 0,
                inode: 0,
                name: "".to_owned()
            }
        ]
    );
}

#[test]
fn test_empty_maps() {
    assert_eq!( parse( "" ), vec![] );
}
