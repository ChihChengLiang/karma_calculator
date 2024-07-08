use phantom_zone::*;

use rand::{thread_rng, Rng, RngCore};

fn sum(a: u8, b: u8, c: u8, total: u8) -> u8 {
    total - (a + b + c)   
}

fn sum_fhe(a: &FheUint8, b: &FheUint8, c: &FheUint8, total: &FheUint8) -> FheUint8 {
   &(&(a + b) + c) - total 
}

fn main() {
    set_parameter_set(ParameterSelector::NonInteractiveLTE4Party);

    // set application's common reference seed
    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);
    set_common_reference_seed(seed);

    let no_of_parties = 3;

    // Clide side //

    // Generate client keys
    let cks = (0..no_of_parties).map(|_| gen_client_key()).collect_vec();

    let users = vec!["Barry", "Justin", "Brian"];
    // Barry score [Barry, Justin, Brian, total]
    let c0 = vec![0,2,4,6]; //thread_rng().gen::<u8>();
    let c0_enc = cks[0].encrypt(c0.as_slice());

    //Justin score [Barry, Justin , Brian , Total]
    let c1 = vec![1,0,1,2]; //thread_rng().gen::<u8>();
    let c1_enc = cks[1].encrypt(c1.as_slice());

    //Brian score [Barry, Justin , Brian , Total]
    let c2 = vec![1,1,0,2];
    let c2_enc = cks[2].encrypt(c2.as_slice());

    let server_key_shares = cks
        .iter()
        .enumerate()
        .map(|(id, k)| gen_server_key_share(id, no_of_parties, k))
        .collect_vec();

    let server_key = aggregate_server_key_shares(&server_key_shares);
    server_key.set_server_key();
    // barry score
    for i in 0..no_of_parties {
        println!("i; {:?}", i);
        let ct_c0_a = c0_enc.unseed::<Vec<Vec<u64>>>().key_switch(0).extract_at(i);
        // plus justin score
        let ct_c1_a = c1_enc.unseed::<Vec<Vec<u64>>>().key_switch(1).extract_at(i);
        // plus brian score 
        let ct_c2_a = c2_enc.unseed::<Vec<Vec<u64>>>().key_switch(2).extract_at(i);
        let a =  c0_enc.unseed::<Vec<Vec<u64>>>().key_switch(i).extract_at(3);
        let b =  c1_enc.unseed::<Vec<Vec<u64>>>().key_switch(i).extract_at(3);
        let c =  c2_enc.unseed::<Vec<Vec<u64>>>().key_switch(i).extract_at(3);
 
        let totals = vec![a, b, c];

        let now = std::time::Instant::now();
        let ct_out_f1 = sum_fhe(&ct_c0_a, &ct_c1_a, &ct_c2_a, &totals[i]);
        println!("Function1 FHE evaluation time: {:?}", now.elapsed());

        let decryption_shares = cks
            .iter()
            .map(|k| k.gen_decryption_share(&ct_out_f1))
            .collect_vec();

        let out_f1 = cks[0].aggregate_decryption_shares(&ct_out_f1, &decryption_shares);

        println!("{:?} score {:?}", users[i] , out_f1 );

        // we check correctness of function1
        //let want_out_f1 = sum(c0[0], c1[0], c2[0], c0[3]);
        //assert_eq!(out_f1, want_out_f1);
    }

}
