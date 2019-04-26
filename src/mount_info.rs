use std::path::{Path, PathBuf};
use std::error::Error;
use std::fs;
use std::fmt;
use std::str;

use crate::utils::read_string_lossy;

#[derive(Debug)]
enum OctalUnescapeError {
    MalformedEscapeCode,
    InvalidUtf8
}

impl fmt::Display for OctalUnescapeError {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> fmt::Result {
        match *self {
            OctalUnescapeError::MalformedEscapeCode => write!( fmt, "malformed escape code" ),
            OctalUnescapeError::InvalidUtf8 => write!( fmt, "invalid utf-8" )
        }
    }
}

impl Error for OctalUnescapeError {}

fn octal_unescape( input: &str ) -> Result< String, OctalUnescapeError > {
    let mut bytes = Vec::with_capacity( input.len() );
    let mut iter = input.as_bytes().iter().cloned();
    while let Some( byte ) = iter.next() {
        if byte == b'\\' {
            let chunk = [
                iter.next().ok_or( OctalUnescapeError::MalformedEscapeCode )?,
                iter.next().ok_or( OctalUnescapeError::MalformedEscapeCode )?,
                iter.next().ok_or( OctalUnescapeError::MalformedEscapeCode )?
            ];

            let chunk = str::from_utf8( &chunk ).ok().ok_or( OctalUnescapeError::MalformedEscapeCode )?;
            let byte = u8::from_str_radix( &chunk, 8 ).ok().ok_or( OctalUnescapeError::MalformedEscapeCode )?;
            bytes.push( byte );

            continue;
        }

        bytes.push( byte );
    }

    let output = String::from_utf8( bytes ).ok().ok_or( OctalUnescapeError::InvalidUtf8 )?;
    Ok( output )
}

#[derive(PartialEq, Debug)]
struct MountInfo {
    mount_id: u32,
    parent_id: Option< u32 >,
    major: u32,
    minor: u32,
    root: PathBuf,
    mount_point: PathBuf,
    filesystem: String,
    mount_source: String
}

impl MountInfo {
    fn effective_root( &self ) -> &Path {
        if self.filesystem == "nfs" {
            if let Some( index ) = self.mount_source.bytes().position( |byte| byte == b':' ) {
                return Path::new( &self.mount_source[ index + 1.. ] );
            }
        }

        return &self.root;
    }
}

#[derive(Debug)]
enum ParseMountInfoError {
    MalformedLine( String ),
    OctalUnescape( String, OctalUnescapeError )
}

impl fmt::Display for ParseMountInfoError {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> fmt::Result {
        match *self {
            ParseMountInfoError::MalformedLine( ref line ) => write!( fmt, "malformed line: '{}'", line ),
            ParseMountInfoError::OctalUnescape( ref line, ref error ) => write!( fmt, "cannot unescape line: {}: '{}'", line, error )
        }
    }
}

impl Error for ParseMountInfoError {}

fn parse_mountinfo( mount_info: &str ) -> Result< Vec< MountInfo >, ParseMountInfoError > {
    let mut output = Vec::new();
    for line in mount_info.split( '\n' ) {
        if line.is_empty() {
            continue;
        }

        let mut iter = line.split( ' ' );
        let mut next = || {
            iter.next().ok_or_else( || ParseMountInfoError::MalformedLine( mount_info.to_string() ) )
        };
        let malformed_err = || {
            ParseMountInfoError::MalformedLine( mount_info.to_string() )
        };
        let octal_unescape_err = |err| {
            ParseMountInfoError::OctalUnescape( mount_info.to_string(), err )
        };

        let mount_id: u32 = next()?.parse().map_err( |_| malformed_err() )?;
        let parent_id: u32 = next()?.parse().map_err( |_| malformed_err() )?;

        let mut major_minor = next()?.split( ':' );
        let major: u32 = major_minor.next().ok_or_else( malformed_err )?.parse().map_err( |_| malformed_err() )?;
        let minor: u32 = major_minor.next().ok_or_else( malformed_err )?.parse().map_err( |_| malformed_err() )?;

        let root = octal_unescape( &next()? ).map_err( octal_unescape_err )?;
        let mount_point = octal_unescape( &next()? ).map_err( octal_unescape_err )?;

        let _mount_options = next()?;
        while next()? != "-" {}

        let filesystem = octal_unescape( &next()? ).map_err( octal_unescape_err )?;
        let mount_source = octal_unescape( &next()? ).map_err( octal_unescape_err )?;

        let info = MountInfo {
            mount_id,
            parent_id: if parent_id == 0 { None } else { Some( parent_id ) },
            major,
            minor,
            root: root.into(),
            mount_point: mount_point.into(),
            filesystem,
            mount_source
        };

        output.push( info );
    }

    Ok( output )
}

#[test]
fn test_parse_mountinfo() {
    let example =
r#"222 114 0:50 / /tmp/path\040with\040a\040space\040\134x rw,relatime shared:120 - tmpfs tmpfs rw
114 23 0:44 / /tmp rw,relatime shared:61 - tmpfs tmpfs rw,size=4194304k
23 0 8:2 / / rw,noatime shared:1 - ext4 /dev/sda2 rw
"#;

    let info = parse_mountinfo( example ).unwrap();
    assert_eq!(
        info,
        vec![
            MountInfo {
                mount_id: 222,
                parent_id: Some( 114 ),
                major: 0,
                minor: 50,
                root: "/".into(),
                mount_point: "/tmp/path with a space \\x".into(),
                filesystem: "tmpfs".into(),
                mount_source: "tmpfs".into()
            },
            MountInfo {
                mount_id: 114,
                parent_id: Some( 23 ),
                major: 0,
                minor: 44,
                root: "/".into(),
                mount_point: "/tmp".into(),
                filesystem: "tmpfs".into(),
                mount_source: "tmpfs".into()
            },
            MountInfo {
                mount_id: 23,
                parent_id: None,
                major: 8,
                minor: 2,
                root: "/".into(),
                mount_point: "/".into(),
                filesystem: "ext4".into(),
                mount_source: "/dev/sda2".into()
            }
        ]
    );
}

pub struct PathResolver {
    self_mount_info: Vec< MountInfo >,
    target_mount_info: Vec< MountInfo >,
    target_root: PathBuf
}

impl PathResolver {
    pub fn new_for_pid( pid: u32 ) -> Result< Self, Box< Error > > {
        let self_mount_info = read_string_lossy( "/proc/self/mountinfo" )
            .map_err( |err| format!( "cannot read /proc/self/mountinfo: {}", err ) )?;

        let target_mount_info = read_string_lossy( &format!( "/proc/{}/mountinfo", pid ) )
            .map_err( |err| format!( "cannot read /proc/{}/mountinfo: {}", pid, err ) )?;

        let target_root = fs::read_link( format!( "/proc/{}/root", pid ) )
            .map_err( |err| format!( "cannot read /proc/{}/root: {}", pid, err ) )?;

        Self::new_from_parts( &self_mount_info, &target_mount_info, target_root )
    }

    fn new_from_parts(
        self_mount_info: &str,
        target_mount_info: &str,
        target_root: PathBuf
    ) -> Result< Self, Box< Error > > {
        let self_mount_info = parse_mountinfo( &self_mount_info )?;
        let target_mount_info = parse_mountinfo( &target_mount_info )?;

        let resolver = PathResolver {
            self_mount_info,
            target_mount_info,
            target_root
        };

        Ok( resolver )
    }

    pub fn resolve< 'a, P: AsRef< Path > >( &'a self, path: P ) -> Option< impl Iterator< Item = PathBuf > + 'a > {
        let path = path.as_ref();
        let path = Path::new( "/" ).join( path.strip_prefix( &self.target_root ).ok()? );

        let target_mount = self.target_mount_info
            .iter()
            .filter( |mount_info| path.starts_with( &mount_info.mount_point ) )
            .max_by_key( |mount_info| mount_info.mount_point.as_os_str().len() )?;

        let candidates = self.self_mount_info
            .iter()
            .filter( move |mount_info| mount_info.major == target_mount.major && mount_info.minor == target_mount.minor )
            .filter( move |mount_info| target_mount.effective_root().starts_with( &mount_info.effective_root() ) );

        let output = candidates.map( move |mount_info| {
            mount_info.mount_point.join( target_mount.effective_root().strip_prefix( &mount_info.effective_root() ).unwrap() ).join( path.file_name().unwrap() )
        });

        Some( output )
    }
}

#[test]
fn test_path_resolver() {
    let self_mount_info = r#"
        903 791 253:3 /user/user/rootfs / rw,noatime - ext4 /dev/mapper/vg01-lxc rw,errors=remount-ro,stripe=320,data=writeback
        905 903 0:264 / /proc rw,nosuid,nodev,noexec,relatime - proc none rw
        906 903 0:265 / /sys rw,nosuid,nodev,noexec,relatime - sysfs none rw
        907 903 0:266 / /dev/shm rw,relatime - tmpfs none rw
        908 903 0:31 / /workspace rw,relatime - nfs xxxxxx98.example.com:/vol/xxxxxx98_home/home/user rw,vers=3,rsize=32768,wsize=32768,namlen=255,soft,proto=tcp,timeo=600,retrans=2,mountaddr=11.111.11.11,mountvers=3,mountport=635,mountproto=udp,local_lock=none,addr=11.111.11.11
        909 903 0:24 / /build/sdkroot rw,relatime - nfs xxxxxx97.example.com:/vol/sdk/sdkroot/sdkroot rw,vers=3,rsize=32768,wsize=32768,namlen=255,soft,proto=tcp,timeo=600,retrans=2,mountaddr=22.222.22.222,mountvers=3,mountport=635,mountproto=udp,local_lock=none,addr=22.222.22.222
        910 903 253:2 /user /var/fpwork/user rw,noatime - ext4 /dev/mapper/vg01-lvol1 rw,errors=remount-ro,stripe=320,data=writeback
        911 903 0:25 / /build/foo rw,relatime - nfs xxxxxx99.example.com:/xxxxxx99_sdk_bin/foo rw,vers=3,rsize=32768,wsize=32768,namlen=255,soft,proto=tcp,timeo=600,retrans=2,mountaddr=12.121.12.12,mountvers=3,mountport=635,mountproto=udp,local_lock=none,addr=12.121.12.12
        912 903 0:23 / /build/bar rw,relatime - nfs xxxxxx98.example.com:/vol/xxxxxx98_bin/build/bar rw,vers=3,rsize=32768,wsize=32768,namlen=255,soft,proto=tcp,timeo=600,retrans=2,mountaddr=11.111.11.11,mountvers=3,mountport=635,mountproto=udp,local_lock=none,addr=11.111.11.11
        913 903 0:13 /129 /dev/console rw,relatime - devpts devpts rw,mode=600,ptmxmode=000
        914 903 0:13 /112 /dev/tty1 rw,relatime - devpts devpts rw,mode=600,ptmxmode=000
        915 903 0:13 /126 /dev/tty2 rw,relatime - devpts devpts rw,mode=600,ptmxmode=000
        916 903 0:13 /127 /dev/tty3 rw,relatime - devpts devpts rw,mode=600,ptmxmode=000
        917 903 0:13 /128 /dev/tty4 rw,relatime - devpts devpts rw,mode=600,ptmxmode=000
        796 903 0:267 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
        797 903 0:267 /ptmx /dev/ptmx rw,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
        798 903 0:268 / /run rw,nosuid,noexec,relatime - tmpfs tmpfs rw,size=9896724k,mode=755
        799 798 0:269 / /run/lock rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=5120k
        800 906 0:41 / /sys/fs/pstore rw,relatime - pstore pstore rw
        801 798 0:270 / /run/shm rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=21431840k
        802 907 0:270 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=21431840k
        806 906 0:271 / /sys/fs/cgroup rw,relatime - tmpfs cgroup rw,size=12k
        818 798 0:272 / /run/cgmanager/fs rw,relatime - tmpfs cgmfs rw,size=100k,mode=755
        820 806 0:45 / /sys/fs/cgroup/systemd rw,nosuid,nodev,noexec,relatime - cgroup systemd rw,release_agent=/run/cgmanager/agents/cgm-release-agent.systemd,name=systemd
        826 798 0:273 / /run/user/0 rw,nosuid,nodev,relatime - tmpfs tmpfs rw,size=9896724k,mode=700
    "#.trim().replace( "        ", "" );

    let target_mount_info = r#"
        1040 1039 253:3 /user/user/rootfs/tmp/pytest-of-root/pytest-2/popen-gw23/sysroot / rw,nosuid,nodev,noatime - ext4 /dev/mapper/vg01-lxc rw,errors=remount-ro,stripe=320,data=writeback
        1058 1040 253:3 /user/user/rootfs/etc/localtime /etc/localtime ro,nosuid,nodev,noatime - ext4 /dev/mapper/vg01-lxc rw,errors=remount-ro,stripe=320,data=writeback
        1059 1040 253:2 /user/checkout/build/x86_64/rootfs/usr/lib64 /foobar/lib rw,nosuid,nodev,noatime - ext4 /dev/mapper/vg01-lvol1 rw,errors=remount-ro,stripe=320,data=writeback
        1060 1040 253:2 /user/checkout/foobar/bin/x86_64 /foobar/bin rw,nosuid,nodev,noatime - ext4 /dev/mapper/vg01-lvol1 rw,errors=remount-ro,stripe=320,data=writeback
        1061 1040 0:24 / /xyz/lib rw,nosuid,nodev,relatime - nfs xxxxxx97.example.com:/vol/sdk/sdkroot/sdkroot/data/C_Platform/XYZ/Lib/LINUX_PC64 rw,vers=3,rsize=32768,wsize=32768,namlen=255,soft,proto=tcp,timeo=600,retrans=2,mountaddr=22.222.22.222,mountvers=3,mountport=635,mountproto=udp,local_lock=none,addr=22.222.22.222
        1041 1040 0:24 / /usr/lib64 ro,nosuid,nodev,relatime - nfs xxxxxx97.example.com:/vol/sdk/sdkroot/sdkroot/data/os/sys-root/x86_64-pc-linux-gnu/usr/lib64 rw,vers=3,rsize=32768,wsize=32768,namlen=255,soft,proto=tcp,timeo=600,retrans=2,mountaddr=22.222.22.222,mountvers=3,mountport=635,mountproto=udp,local_lock=none,addr=22.222.22.222
        1042 1040 0:24 / /lib64 ro,nosuid,nodev,relatime - nfs xxxxxx97.example.com:/vol/sdk/sdkroot/sdkroot/data/os/sys-root/x86_64-pc-linux-gnu/usr/lib64 rw,vers=3,rsize=32768,wsize=32768,namlen=255,soft,proto=tcp,timeo=600,retrans=2,mountaddr=22.222.22.222,mountvers=3,mountport=635,mountproto=udp,local_lock=none,addr=22.222.22.222
        1043 1040 0:24 / /usr/bin ro,nosuid,nodev,relatime - nfs xxxxxx97.example.com:/vol/sdk/sdkroot/sdkroot/data/os/sys-root/x86_64-pc-linux-gnu/usr/bin rw,vers=3,rsize=32768,wsize=32768,namlen=255,soft,proto=tcp,timeo=600,retrans=2,mountaddr=22.222.22.222,mountvers=3,mountport=635,mountproto=udp,local_lock=none,addr=22.222.22.222
        1044 1040 0:290 / /dev rw,nosuid,nodev,relatime - tmpfs tmpfs rw,mode=755
        1053 1040 0:264 / /proc rw,nosuid,nodev,noexec,relatime - proc none rw
        1062 1040 0:24 / /xyz/bin rw,nosuid,nodev,relatime - nfs xxxxxx97.example.com:/vol/sdk/sdkroot/sdkroot/data/C_Platform/XYZ/Exe/LINUX_PC64 rw,vers=3,rsize=32768,wsize=32768,namlen=255,soft,proto=tcp,timeo=600,retrans=2,mountaddr=22.222.22.222,mountvers=3,mountport=635,mountproto=udp,local_lock=none,addr=22.222.22.222
        1045 1044 253:3 /user/user/rootfs/dev/null /dev/null rw,nosuid,noatime - ext4 /dev/mapper/vg01-lxc rw,errors=remount-ro,stripe=320,data=writeback
        1046 1044 253:3 /user/user/rootfs/dev/zero /dev/zero rw,nosuid,noatime - ext4 /dev/mapper/vg01-lxc rw,errors=remount-ro,stripe=320,data=writeback
        1047 1044 253:3 /user/user/rootfs/dev/full /dev/full rw,nosuid,noatime - ext4 /dev/mapper/vg01-lxc rw,errors=remount-ro,stripe=320,data=writeback
        1048 1044 253:3 /user/user/rootfs/dev/random /dev/random rw,nosuid,noatime - ext4 /dev/mapper/vg01-lxc rw,errors=remount-ro,stripe=320,data=writeback
        1049 1044 253:3 /user/user/rootfs/dev/urandom /dev/urandom rw,nosuid,noatime - ext4 /dev/mapper/vg01-lxc rw,errors=remount-ro,stripe=320,data=writeback
        1050 1044 253:3 /user/user/rootfs/dev/tty /dev/tty rw,nosuid,noatime - ext4 /dev/mapper/vg01-lxc rw,errors=remount-ro,stripe=320,data=writeback
        1051 1044 0:291 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,mode=620,ptmxmode=666
        1052 1044 0:270 /pytest-of-root/pytest-109/xyzdaemon /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=21431840k
        1054 1053 0:264 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc none rw
        1055 1053 0:264 /sysrq-trigger /proc/sysrq-trigger ro,nosuid,nodev,noexec,relatime - proc none rw
        1056 1053 0:264 /irq /proc/irq ro,nosuid,nodev,noexec,relatime - proc none rw
        1057 1053 0:264 /bus /proc/bus ro,nosuid,nodev,noexec,relatime - proc none rw
    "#.trim().replace( "        ", "" );

    let target_root: PathBuf = "/newroot".into();

    let resolver = PathResolver::new_from_parts( &self_mount_info, &target_mount_info, target_root ).unwrap();

    let paths: Vec< _ > = resolver.resolve( "/newroot/foobar/bin/Foobar" ).unwrap().collect();
    assert_eq!(
        paths,
        vec![ Path::new( "/var/fpwork/user/checkout/foobar/bin/x86_64/Foobar" ) ]
    );

    let paths: Vec< _ > = resolver.resolve( "/newroot/lib64/libnss_files-2.28.so" ).unwrap().collect();
    assert_eq!(
        paths,
        vec![ Path::new( "/build/sdkroot/data/os/sys-root/x86_64-pc-linux-gnu/usr/lib64/libnss_files-2.28.so" ) ]
    );
}
