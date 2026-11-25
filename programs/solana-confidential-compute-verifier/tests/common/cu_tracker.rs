use std::sync::Mutex;

const REPORT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../cu_report.md");

static RECORDS: Mutex<Vec<(String, u64)>> = Mutex::new(Vec::new());

pub fn record_cu(name: &str, cus: u64) {
    if std::env::var_os("CU_REPORT").is_none() {
        return;
    }
    let mut records = RECORDS.lock().expect("CU record lock poisoned");
    records.push((name.to_string(), cus));
    let mut markdown = String::from("# Compute Unit Report\n\n| Instruction | Compute units |\n| --- | ---: |\n");
    for (instruction, units) in records.iter() {
        markdown.push_str(&format!("| {instruction} | {units} |\n"));
    }
    std::fs::write(REPORT_PATH, markdown).expect("write cu_report.md");
}
