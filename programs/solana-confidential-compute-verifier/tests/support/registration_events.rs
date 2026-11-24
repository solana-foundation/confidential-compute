use std::cell::RefCell;

thread_local! {
    static EVENTS: RefCell<Vec<Vec<Vec<u8>>>> = const { RefCell::new(Vec::new()) };
}

pub fn record(fields: &[&[u8]]) {
    if fields.first() == Some(&b"solana-confidential-compute:registration:v1".as_slice()) {
        EVENTS.with(|events| events.borrow_mut().push(fields.iter().map(|v| v.to_vec()).collect()));
    }
}

pub fn clear() {
    EVENTS.with(|events| events.borrow_mut().clear());
}

pub fn assert_empty() {
    EVENTS.with(|events| assert!(events.borrow().is_empty(), "failed call emitted a registration event"));
}

pub fn assert_event(
    operation: &[u8],
    source: &[u8],
    subject: &[u8],
    account: &solana_program::account_info::AccountInfo,
) {
    EVENTS.with(|events| {
        let observed = events.replace(Vec::new());
        assert_eq!(observed.len(), 1, "one success event per registration");
        assert_eq!(
            observed[0],
            vec![
                b"solana-confidential-compute:registration:v1".to_vec(),
                operation.to_vec(),
                source.to_vec(),
                subject.to_vec(),
                account.key.to_bytes().to_vec(),
                solana_program::hash::hashv(&[&account.try_borrow_data().unwrap()]).to_bytes().to_vec(),
            ]
        );
    });
}
