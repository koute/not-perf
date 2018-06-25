#[derive(Debug, Deserialize, Serialize)]
pub struct MachineInfo {
    pub architecture: String
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Process {
    pub pid: u32,
    pub executable: String
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Binary {
    pub path: String,
    pub debuglink: Option< String >,
    pub build_id: Option< String >
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Metadata {
    pub machine_info: Option< MachineInfo >,
    pub processes: Vec< Process >,
    pub binaries: Vec< Binary >
}
