#[derive(Debug)]
pub struct Collaterals {
    pub tcb_info: Vec<u8>,
    pub qe_identity: Vec<u8>,
    pub root_ca: Vec<u8>,
    pub tcb_signing_ca: Vec<u8>,
    pub root_ca_crl: Vec<u8>,
    pub pck_crl: Vec<u8>
}

impl Collaterals {
    pub fn new(
        tcb_info: Vec<u8>,
        qe_identity: Vec<u8>,
        root_ca: Vec<u8>,
        tcb_signing_ca: Vec<u8>,
        root_ca_crl: Vec<u8>,
        pck_crl: Vec<u8>
    ) -> Self {
        Collaterals {
            tcb_info,
            qe_identity,
            root_ca,
            tcb_signing_ca,
            root_ca_crl,
            pck_crl
        }
    }
}