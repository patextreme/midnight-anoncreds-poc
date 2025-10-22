use std::collections::{BTreeSet, HashMap};
use std::fs::create_dir;

use anoncreds::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
use anoncreds::data_types::cred_offer::CredentialOffer;
use anoncreds::data_types::credential::Credential;
use anoncreds::data_types::nonce::Nonce;
use anoncreds::data_types::presentation::Presentation;
use anoncreds::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use anoncreds::data_types::schema::{Schema, SchemaId};
use anoncreds::data_types::w3c::VerifiableCredentialSpecVersion;
use anoncreds::data_types::w3c::credential::W3CCredential;
use anoncreds::data_types::w3c::credential_attributes::{CredentialAttributeValue, CredentialSubject};
use anoncreds::data_types::w3c::presentation::W3CPresentation;
use anoncreds::tails::TailsFileWriter;
use anoncreds::types::{
    CredentialDefinitionConfig, CredentialRequest, CredentialRequestMetadata, CredentialRevocationConfig,
    CredentialRevocationState, CredentialValues, MakeCredentialValues, PresentCredentials, PresentationRequest,
    RegistryType, RevocationRegistryDefinition, RevocationStatusList, SignatureType,
};
use anoncreds::w3c::credential_conversion::{credential_from_w3c, credential_to_w3c};
use anoncreds::w3c::types::MakeCredentialAttributes;
use anoncreds::{issuer, prover, verifier, w3c};
use serde::Serialize;
use serde_json::json;

use super::storage::{IssuerWallet, Ledger, ProverWallet, StoredCredDef, StoredRevDef};
use crate::utils::{VerifierWallet, fixtures};

#[derive(Debug)]
pub struct TestError(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialFormat {
    Legacy,
    W3C,
}

#[derive(Debug)]
pub enum Credentials {
    Legacy(Credential),
    W3C(W3CCredential),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresentationFormat {
    Legacy,
    W3C,
}

#[derive(Debug, Serialize)]
pub enum Presentations {
    Legacy(Presentation),
    W3C(W3CPresentation),
}

impl Credentials {
    pub fn legacy(&self) -> &Credential {
        match self {
            Credentials::Legacy(credential) => credential,
            _ => panic!("Legacy credential expected"),
        }
    }

    pub fn w3c(&self) -> &W3CCredential {
        match self {
            Credentials::W3C(credential) => credential,
            _ => panic!("W3C credential expected"),
        }
    }
}

impl Presentations {
    pub fn legacy(&self) -> &Presentation {
        match self {
            Presentations::Legacy(presentation) => presentation,
            _ => panic!("Legacy presentation expected"),
        }
    }

    pub fn w3c(&self) -> &W3CPresentation {
        match self {
            Presentations::W3C(presentation) => presentation,
            _ => panic!("W3C presentation expected"),
        }
    }
}

impl<'a> Ledger<'a> {
    pub fn add_schema(&mut self, schema_id: &str, schema: &Schema) {
        let schema_id = SchemaId::new_unchecked(schema_id);
        self.schemas.insert(schema_id, schema.clone());
    }

    pub fn add_cred_def(&mut self, cred_def_id: &str, cred_def: &CredentialDefinition) {
        let cred_def_id = CredentialDefinitionId::new_unchecked(cred_def_id);
        self.cred_defs.insert(cred_def_id, cred_def.try_clone().unwrap());
    }

    pub fn add_rev_reg_def(&mut self, rev_reg_def_id: &str, rev_reg_def: &RevocationRegistryDefinition) {
        let rev_reg_def_id = RevocationRegistryDefinitionId::new_unchecked(rev_reg_def_id);
        self.rev_reg_defs.insert(rev_reg_def_id, rev_reg_def.clone());
    }

    pub fn resolve_schemas(&self, schema_ids: Vec<&str>) -> HashMap<SchemaId, Schema> {
        let mut schemas = HashMap::new();
        for schema_id in schema_ids {
            let schema_id = SchemaId::new_unchecked(schema_id);
            let schema = self.schemas.get(&schema_id).expect("Schema not found");
            schemas.insert(schema_id, schema.clone());
        }
        schemas
    }

    pub fn resolve_cred_defs(&self, cred_def_ids: Vec<&str>) -> HashMap<CredentialDefinitionId, CredentialDefinition> {
        let mut cred_defs = HashMap::new();
        for cred_def_id in cred_def_ids {
            let cred_def_id = CredentialDefinitionId::new_unchecked(cred_def_id);
            let cred_def = self.cred_defs.get(&cred_def_id).expect("CredDef not found");
            cred_defs.insert(cred_def_id, cred_def.try_clone().unwrap());
        }
        cred_defs
    }

    pub fn resolve_rev_reg_defs(
        &self,
        rev_reg_def_ids: Vec<&str>,
    ) -> HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition> {
        let mut rev_reg_def_map = HashMap::new();
        for rev_reg_def_id in rev_reg_def_ids {
            let rev_reg_def_id = RevocationRegistryDefinitionId::new_unchecked(rev_reg_def_id);
            let rev_reg_def = self.rev_reg_defs.get(&rev_reg_def_id).expect("RevRegDef not found");
            rev_reg_def_map.insert(rev_reg_def_id, rev_reg_def.clone());
        }
        rev_reg_def_map
    }
}

impl IssuerWallet {
    pub fn create_schema(&self, ledger: &mut Ledger, name: &str) -> (Schema, String) {
        let (schema, schema_id) = fixtures::create_schema(name);
        ledger.add_schema(schema_id, &schema);
        (schema, schema_id.to_string())
    }

    pub fn create_cred_def(
        &mut self,
        ledger: &mut Ledger,
        schema: &Schema,
        support_revocation: bool,
    ) -> (CredentialDefinition, String) {
        let ((cred_def, cred_def_priv, cred_key_correctness_proof), cred_def_id) =
            fixtures::create_cred_def(schema, support_revocation);
        ledger.add_cred_def(cred_def_id, &cred_def);
        self.cred_defs.insert(
            cred_def_id.to_string(),
            StoredCredDef {
                public: cred_def.try_clone().unwrap(),
                private: cred_def_priv,
                key_proof: cred_key_correctness_proof,
            },
        );
        (cred_def, cred_def_id.to_string())
    }

    pub fn create_revocation_registry<'b>(
        &mut self,
        ledger: &mut Ledger,
        cred_def: &CredentialDefinition,
        time: Option<u64>,
        issuance_by_default: bool,
    ) -> (String, RevocationRegistryDefinition, RevocationStatusList) {
        // Create tails file writer
        let mut tf = TailsFileWriter::new(None);

        let ((rev_reg_def, rev_reg_def_priv), rev_reg_def_id) = fixtures::create_rev_reg_def(cred_def, &mut tf);

        // Issuer creates revocation status list - to be put on the ledger
        let revocation_status_list = fixtures::create_revocation_status_list(
            cred_def,
            &rev_reg_def,
            &rev_reg_def_priv,
            time,
            issuance_by_default,
        );

        self.rev_defs.insert(
            rev_reg_def_id.to_string(),
            StoredRevDef {
                public: rev_reg_def.clone(),
                private: rev_reg_def_priv,
            },
        );

        ledger.add_rev_reg_def(rev_reg_def_id, &rev_reg_def);

        (rev_reg_def_id.to_string(), rev_reg_def, revocation_status_list)
    }

    pub fn create_credential_offer(&self, schema_id: &str, cred_def_id: &str) -> CredentialOffer {
        let correctness_proof = &self
            .cred_defs
            .get(cred_def_id)
            .expect("Credential Definition correctness proof not found")
            .key_proof;
        issuer::create_credential_offer(
            schema_id.try_into().unwrap(),
            cred_def_id.try_into().unwrap(),
            correctness_proof,
        )
        .expect("Error creating credential offer")
    }

    pub fn create_credential(
        &self,
        format: &CredentialFormat,
        cred_def_id: &str,
        cred_offer: &CredentialOffer,
        cred_request: &CredentialRequest,
        cred_values: CredentialValues,
        rev_reg_def_id: Option<&str>,
        revocation_status_list: Option<&RevocationStatusList>,
        credential_rev_index: Option<u32>,
        version: Option<VerifiableCredentialSpecVersion>,
    ) -> Credentials {
        let cred_def_record = &self
            .cred_defs
            .get(cred_def_id)
            .expect("Credential Definition not found");
        let cred_def_private = &cred_def_record.private;
        let cred_def = &cred_def_record.public;

        let revocation_config = match rev_reg_def_id {
            Some(rev_reg_def_id) => {
                self.rev_defs
                    .get(rev_reg_def_id)
                    .map(|stored_rev_def| CredentialRevocationConfig {
                        reg_def: &stored_rev_def.public,
                        reg_def_private: &stored_rev_def.private,
                        registry_idx: credential_rev_index.expect("Credential Revocation Index must be provided"),
                        status_list: revocation_status_list.expect("Missing status list"),
                    })
            }
            None => None,
        };

        let credential = match format {
            CredentialFormat::Legacy => {
                let issue_cred = issuer::create_credential(
                    cred_def,
                    cred_def_private,
                    &cred_offer,
                    &cred_request,
                    cred_values,
                    revocation_config,
                )
                .expect("Error creating credential");
                Credentials::Legacy(issue_cred)
            }
            CredentialFormat::W3C => {
                let issue_cred = w3c::issuer::create_credential(
                    cred_def,
                    cred_def_private,
                    &cred_offer,
                    &cred_request,
                    CredentialSubject::try_from(&cred_values).expect("Error generating credential attributes"),
                    revocation_config,
                    version,
                )
                .expect("Error creating credential");
                Credentials::W3C(issue_cred)
            }
        };

        credential
    }

    pub fn update_revocation_status_list(
        &self,
        cred_def: &CredentialDefinition,
        rev_reg_def_id: &str,
        current_list: &RevocationStatusList,
        issued: Option<BTreeSet<u32>>,
        revoked: Option<BTreeSet<u32>>,
        timestamp: Option<u64>,
    ) -> RevocationStatusList {
        let rev_reg = self
            .rev_defs
            .get(rev_reg_def_id)
            .expect("Revocation Registry Definition not found");
        issuer::update_revocation_status_list(
            cred_def,
            &rev_reg.public,
            &rev_reg.private,
            current_list,
            issued,
            revoked,
            timestamp,
        )
        .unwrap()
    }
}

impl<'a> ProverWallet<'a> {
    pub fn create_credential_request(
        &self,
        cred_def: &CredentialDefinition,
        credential_offer: &CredentialOffer,
    ) -> (CredentialRequest, CredentialRequestMetadata) {
        prover::create_credential_request(
            Some(self.entropy),
            None,
            cred_def,
            &self.link_secret,
            &self.link_secret_id,
            credential_offer,
        )
        .expect("Error creating credential request")
    }

    pub fn store_credential(
        &mut self,
        id: &str,
        credential: &mut Credentials,
        cred_request_metadata: &CredentialRequestMetadata,
        cred_def: &CredentialDefinition,
        rev_reg_def: Option<&RevocationRegistryDefinition>,
    ) {
        match credential {
            Credentials::Legacy(credential) => {
                prover::process_credential(
                    credential,
                    cred_request_metadata,
                    &self.link_secret,
                    cred_def,
                    rev_reg_def,
                )
                .expect("Error processing credential");
                self.credentials.insert(id.to_string(), credential.try_clone().unwrap());
            }
            Credentials::W3C(credential) => {
                w3c::prover::process_credential(
                    credential,
                    cred_request_metadata,
                    &self.link_secret,
                    cred_def,
                    rev_reg_def,
                )
                .expect("Error processing credential");
                self.w3c_credentials.insert(id.to_string(), credential.clone());
            }
        }
    }

    pub fn create_or_update_revocation_state(
        &self,
        tails_location: &str,
        rev_reg_def: &RevocationRegistryDefinition,
        rev_status_list: &RevocationStatusList,
        rev_reg_idx: u32,
        rev_state: Option<&CredentialRevocationState>,
        old_rev_status_list: Option<&RevocationStatusList>,
    ) -> CredentialRevocationState {
        prover::create_or_update_revocation_state(
            tails_location,
            &rev_reg_def,
            rev_status_list,
            rev_reg_idx,
            rev_state,
            old_rev_status_list,
        )
        .expect("Error creating revocation state")
    }

    pub fn prepare_credentials_to_present<'b, T: RevocableCredential>(
        &'b self,
        credentials: &'b HashMap<String, T>,
        present_credentials: &Vec<CredentialToPresent>,
    ) -> PresentCredentials<'b, T> {
        let mut present = PresentCredentials::default();

        for present_credential in present_credentials.iter() {
            let credential = credentials.get(&present_credential.id).expect("Credential not found");

            let (rev_state, timestamp) = if let Some(id) = &credential.rev_reg_id() {
                self.rev_states.get(&id.0).unwrap()
            } else {
                &(None, None)
            };

            let mut cred = present.add_credential(credential, *timestamp, rev_state.as_ref());
            for data in present_credential.attributes.iter() {
                match data.form {
                    PresentAttributeForm::RevealedAttribute => {
                        cred.add_requested_attribute(&data.referent, true);
                    }
                    PresentAttributeForm::UnrevealedAttribute => {
                        cred.add_requested_attribute(&data.referent, false);
                    }
                    PresentAttributeForm::Predicate => {
                        cred.add_requested_predicate(&data.referent);
                    }
                }
            }
        }
        present
    }

    pub fn create_presentation(
        &self,
        format: &PresentationFormat,
        schemas: &HashMap<SchemaId, Schema>,
        cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
        pres_request: &PresentationRequest,
        present_credentials: &Vec<CredentialToPresent>,
        self_attested_credentials: Option<HashMap<String, String>>,
        version: Option<VerifiableCredentialSpecVersion>,
    ) -> Presentations {
        match format {
            PresentationFormat::Legacy => {
                let present = self.prepare_credentials_to_present(&self.credentials, present_credentials);
                let presentation = prover::create_presentation(
                    pres_request,
                    present,
                    self_attested_credentials,
                    &self.link_secret,
                    schemas,
                    cred_defs,
                )
                .expect("Error creating presentation");
                Presentations::Legacy(presentation)
            }
            PresentationFormat::W3C => {
                let present = self.prepare_credentials_to_present(&self.w3c_credentials, present_credentials);
                let presentation = w3c::prover::create_presentation(
                    pres_request,
                    present,
                    &self.link_secret,
                    schemas,
                    cred_defs,
                    version,
                )
                .expect("Error creating presentation");
                Presentations::W3C(presentation)
            }
        }
    }

    pub fn convert_credential(&mut self, id: &str, credential: &Credentials, cred_def: &CredentialDefinition) {
        match credential {
            Credentials::Legacy(legacy_cred) => {
                // Convert legacy credential into W3C form
                let w3c_cred = credential_to_w3c(&legacy_cred, &cred_def.issuer_id, None)
                    .expect("Error converting legacy credential into W3C form");

                // Store w3c credential in wallet
                self.w3c_credentials.insert(id.to_string(), w3c_cred);
            }
            Credentials::W3C(w3c_cred) => {
                // Convert w3c credential into legacy form
                let legacy_cred =
                    credential_from_w3c(&w3c_cred).expect("Error converting legacy credential into W3C form");

                // Store legacy credential in wallet
                self.credentials.insert(id.to_string(), legacy_cred);
            }
        }
    }
}

impl VerifierWallet {
    pub fn generate_nonce(&self) -> Nonce {
        verifier::generate_nonce().expect("Error generating presentation request nonce")
    }

    pub fn verify_presentation(
        &self,
        presentation: &Presentations,
        pres_req: &PresentationRequest,
        schemas: &HashMap<SchemaId, Schema>,
        cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
        rev_reg_defs: Option<&HashMap<RevocationRegistryDefinitionId, RevocationRegistryDefinition>>,
        rev_status_lists: Option<Vec<RevocationStatusList>>,
        nonrevoke_interval_override: Option<&HashMap<RevocationRegistryDefinitionId, HashMap<u64, u64>>>,
    ) -> Result<bool, TestError> {
        match presentation {
            Presentations::Legacy(presentation) => verifier::verify_presentation(
                presentation,
                pres_req,
                schemas,
                cred_defs,
                rev_reg_defs,
                rev_status_lists,
                nonrevoke_interval_override,
            )
            .map_err(|e| TestError(e.to_string())),
            Presentations::W3C(presentation) => w3c::verifier::verify_presentation(
                presentation,
                pres_req,
                schemas,
                cred_defs,
                rev_reg_defs,
                rev_status_lists,
                nonrevoke_interval_override,
            )
            .map_err(|e| TestError(e.to_string())),
        }
    }

    pub fn check_presentation_attribute(&self, presentation: &Presentations, attribute: PresentedAttribute) {
        match presentation {
            Presentations::Legacy(presentation) => {
                match attribute.expected {
                    ExpectedAttributeValue::RevealedAttribute(expected) => {
                        assert_eq!(
                            expected.to_string(),
                            presentation
                                .requested_proof
                                .revealed_attrs
                                .get(attribute.referent)
                                .unwrap()
                                .raw
                        );
                    }
                    ExpectedAttributeValue::GroupedAttribute(expected) => {
                        let revealed_attr_groups = presentation
                            .requested_proof
                            .revealed_attr_groups
                            .get(attribute.referent)
                            .unwrap();
                        assert_eq!(
                            expected.to_string(),
                            revealed_attr_groups.values.get(attribute.name).unwrap().raw
                        );
                    }
                    ExpectedAttributeValue::UnrevealedAttribute(expected) => {
                        assert_eq!(
                            expected,
                            presentation
                                .requested_proof
                                .unrevealed_attrs
                                .get(attribute.referent)
                                .unwrap()
                                .sub_proof_index
                        );
                    }
                    ExpectedAttributeValue::Predicate => {
                        presentation.requested_proof.predicates.get(attribute.referent).unwrap();
                    }
                };
            }
            Presentations::W3C(presentation) => {
                match attribute.expected {
                    ExpectedAttributeValue::RevealedAttribute(expected)
                    | ExpectedAttributeValue::GroupedAttribute(expected) => {
                        let credential = presentation
                            .verifiable_credential
                            .iter()
                            .find(|credential| {
                                credential
                                    .credential_subject
                                    .0
                                    .contains_key(&attribute.name.to_lowercase())
                            })
                            .unwrap();

                        assert_eq!(
                            expected,
                            credential
                                .credential_subject
                                .0
                                .get(&attribute.name.to_lowercase())
                                .unwrap()
                                .clone()
                        );
                    }
                    ExpectedAttributeValue::UnrevealedAttribute(expected) => {
                        // not checking here
                    }
                    ExpectedAttributeValue::Predicate => {
                        let credential = presentation
                            .verifiable_credential
                            .iter()
                            .find(|credential| {
                                credential
                                    .credential_subject
                                    .0
                                    .contains_key(&attribute.name.to_lowercase())
                            })
                            .unwrap();
                        credential
                            .credential_subject
                            .0
                            .get(&attribute.name.to_lowercase())
                            .unwrap();
                    }
                };
            }
        }
    }
}

pub struct CredentialToPresent {
    pub id: String,
    pub attributes: Vec<PresentAttribute>,
}

pub struct PresentAttribute {
    pub referent: String,
    pub form: PresentAttributeForm,
}

pub enum PresentAttributeForm {
    RevealedAttribute,
    UnrevealedAttribute,
    Predicate,
}

pub struct PresentedAttribute<'a> {
    pub referent: &'a str,
    pub name: &'a str,
    pub expected: ExpectedAttributeValue,
}

pub enum ExpectedAttributeValue {
    RevealedAttribute(CredentialAttributeValue),
    UnrevealedAttribute(u32),
    GroupedAttribute(CredentialAttributeValue),
    Predicate,
}

pub trait RevocableCredential {
    fn rev_reg_id(&self) -> Option<RevocationRegistryDefinitionId>;
}

impl RevocableCredential for Credential {
    fn rev_reg_id(&self) -> Option<RevocationRegistryDefinitionId> {
        self.rev_reg_id.clone()
    }
}

impl RevocableCredential for W3CCredential {
    fn rev_reg_id(&self) -> Option<RevocationRegistryDefinitionId> {
        self.get_credential_signature_proof()
            .ok()
            .and_then(|proof| proof.rev_reg_id.clone())
    }
}
