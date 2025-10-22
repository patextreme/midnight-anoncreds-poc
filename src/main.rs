mod utils;

use std::collections::BTreeSet;

use serde_json::json;
use sha2::{Digest, Sha256};
use utils::*;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let credential_format = CredentialFormat::W3C;
    let presentation_format = PresentationFormat::W3C;

    // Create pseudo ledger and wallets
    let mut ledger = Ledger::default();
    let mut issuer_wallet = IssuerWallet::default();
    let mut prover_wallet = ProverWallet::default();
    let verifier_wallet = VerifierWallet::default();

    // Create schema
    let (gvt_schema, gvt_schema_id) = issuer_wallet.create_schema(&mut ledger, GVT_CRED);

    // Create credential definition
    let (gvt_cred_def, gvt_cred_def_id) = issuer_wallet.create_cred_def(&mut ledger, &gvt_schema, true);

    // Create revocation registry
    let time_create_rev_status_list = 12;
    let (gvt_rev_reg_def_id, gvt_rev_reg_def, gvt_revocation_status_list) =
        issuer_wallet.create_revocation_registry(&mut ledger, &gvt_cred_def, Some(time_create_rev_status_list), true);

    // Issuer creates a Credential Offer
    let cred_offer = issuer_wallet.create_credential_offer(&gvt_schema_id, &gvt_cred_def_id);

    // Prover creates a Credential Request
    let (cred_request, cred_request_metadata) = prover_wallet.create_credential_request(&gvt_cred_def, &cred_offer);

    //---------------------
    // Revocation handle
    //---------------------
    let link_secret_str: String = prover_wallet.link_secret.try_clone().unwrap().try_into().unwrap();
    let _link_secret_hash = format!("{:x}", Sha256::digest(link_secret_str.as_bytes()));

    // Issuer creates a credential
    let cred_values = fixtures::credential_values(GVT_CRED);

    // Get the location of the tails_file so it can be read
    let tails_location = gvt_rev_reg_def.value.tails_location.clone();

    let issue_cred = issuer_wallet.create_credential(
        &credential_format,
        &gvt_cred_def_id,
        &cred_offer,
        &cred_request,
        cred_values.into(),
        Some(&gvt_rev_reg_def_id),
        Some(&gvt_revocation_status_list),
        Some(fixtures::GVT_REV_IDX),
        None,
    );

    let time_after_creating_cred = time_create_rev_status_list + 1;
    let issued_rev_status_list = issuer_wallet.update_revocation_status_list(
        &gvt_cred_def,
        &gvt_rev_reg_def_id,
        &gvt_revocation_status_list,
        Some(BTreeSet::from([fixtures::GVT_REV_IDX])),
        None,
        Some(time_after_creating_cred),
    );

    // Prover receives the credential and processes it
    let mut rec_cred = issue_cred;
    prover_wallet.store_credential(
        GVT_CRED,
        &mut rec_cred,
        &cred_request_metadata,
        &gvt_cred_def,
        Some(&gvt_rev_reg_def),
    );

    // Verifier creates a presentation request
    // There are fields for
    // - global non_revoked - i.e. the PresentationRequest level
    // - local non_revoked - i.e. Each Request Attributes (AttributeInfo) and Request Predicate (PredicateInfo) has a field for NonRevoked.
    let nonce = verifier_wallet.generate_nonce();
    let pres_request = serde_json::from_value(json!({
        "nonce": nonce,
        "name":"pres_req_1",
        "version":"0.1",
        "requested_attributes":{
            "attr1_referent":{
                "name":"name",
                "issuer_id": GVT_ISSUER_ID
            },
            "attr2_referent":{
                "name":"sex"
            },
            "attr3_referent":{
                "names": ["name", "height"]
            }
        },
        "requested_predicates":{
            "predicate1_referent":{"name":"age","p_type":">=","p_value":18}
        },
        "non_revoked": {"from": 10, "to": 200}
    }))
    .expect("Error creating proof request");

    let rev_state = prover_wallet.create_or_update_revocation_state(
        &tails_location,
        &gvt_rev_reg_def,
        &gvt_revocation_status_list,
        fixtures::GVT_REV_IDX,
        None,
        None,
    );
    prover_wallet.rev_states.insert(
        gvt_rev_reg_def_id.to_string(),
        (Some(rev_state.clone()), Some(time_after_creating_cred)),
    );

    let schemas = ledger.resolve_schemas(vec![&gvt_schema_id]);
    let cred_defs = ledger.resolve_cred_defs(vec![&gvt_cred_def_id]);
    let rev_reg_def_map = ledger.resolve_rev_reg_defs(vec![&gvt_rev_reg_def_id]);

    let mut rev_status_list = vec![issued_rev_status_list.clone()];

    // Prover creates presentation
    let present_credentials = vec![CredentialToPresent {
        id: GVT_CRED.to_string(),
        attributes: vec![
            PresentAttribute {
                referent: "attr1_referent".to_string(),
                form: PresentAttributeForm::RevealedAttribute,
            },
            PresentAttribute {
                referent: "attr2_referent".to_string(),
                form: PresentAttributeForm::UnrevealedAttribute,
            },
            PresentAttribute {
                referent: "attr3_referent".to_string(),
                form: PresentAttributeForm::RevealedAttribute,
            },
            PresentAttribute {
                referent: "predicate1_referent".to_string(),
                form: PresentAttributeForm::Predicate,
            },
        ],
    }];

    let presentation = prover_wallet.create_presentation(
        &presentation_format,
        &schemas,
        &cred_defs,
        &pres_request,
        &present_credentials,
        None,
        None,
    );

    let valid = verifier_wallet
        .verify_presentation(
            &presentation,
            &pres_request,
            &schemas,
            &cred_defs,
            Some(&rev_reg_def_map),
            Some(rev_status_list.clone()),
            None,
        )
        .unwrap();

    assert!(valid);

    //  ===================== Issuer revokes credential ================
    let time_revoke_cred = time_after_creating_cred + 1;

    let revoked_status_list = issuer_wallet.update_revocation_status_list(
        &gvt_cred_def,
        &gvt_rev_reg_def_id,
        &issued_rev_status_list,
        None,
        Some(BTreeSet::from([fixtures::GVT_REV_IDX])),
        Some(time_revoke_cred),
    );

    rev_status_list.push(revoked_status_list.clone());

    let rev_state = prover_wallet.create_or_update_revocation_state(
        &tails_location,
        &gvt_rev_reg_def,
        &revoked_status_list,
        fixtures::GVT_REV_IDX,
        Some(&rev_state),
        Some(&issued_rev_status_list),
    );
    prover_wallet.rev_states.insert(
        gvt_rev_reg_def_id.to_string(),
        (Some(rev_state), Some(time_revoke_cred)),
    );

    // Prover creates presentation
    let present_credentials = vec![CredentialToPresent {
        id: GVT_CRED.to_string(),
        attributes: vec![
            PresentAttribute {
                referent: "attr1_referent".to_string(),
                form: PresentAttributeForm::RevealedAttribute,
            },
            PresentAttribute {
                referent: "attr2_referent".to_string(),
                form: PresentAttributeForm::UnrevealedAttribute,
            },
            PresentAttribute {
                referent: "attr3_referent".to_string(),
                form: PresentAttributeForm::RevealedAttribute,
            },
            PresentAttribute {
                referent: "predicate1_referent".to_string(),
                form: PresentAttributeForm::Predicate,
            },
        ],
    }];

    let presentation = prover_wallet.create_presentation(
        &presentation_format,
        &schemas,
        &cred_defs,
        &pres_request,
        &present_credentials,
        None,
        None,
    );

    let valid = verifier_wallet
        .verify_presentation(
            &presentation,
            &pres_request,
            &schemas,
            &cred_defs,
            Some(&rev_reg_def_map),
            Some(rev_status_list),
            None,
        )
        .unwrap();

    assert!(!valid);

    Ok(())
}
