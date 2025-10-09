use std::collections::HashMap;

use anoncreds::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
use anoncreds::data_types::rev_reg_def::RevocationRegistryDefinitionId;
use anoncreds::data_types::schema::{Schema, SchemaId};
use anoncreds::prover;
use anoncreds::types::*;

use crate::vdr::Vdr;

pub struct Prover {
    pub link_secret: LinkSecret,
    pub credentials: Vec<Credential>,
    #[allow(dead_code)]
    pub credential_metadata: HashMap<String, CredentialRequestMetadata>,
    #[allow(dead_code)]
    pub revocation_states: HashMap<RevocationRegistryDefinitionId, CredentialRevocationState>,
    #[allow(dead_code)]
    pub cached_schemas: HashMap<SchemaId, Schema>,
    pub cached_cred_defs: HashMap<CredentialDefinitionId, CredentialDefinition>,
}

impl Prover {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            link_secret: prover::create_link_secret()?,
            credentials: Vec::new(),
            credential_metadata: HashMap::new(),
            revocation_states: HashMap::new(),
            cached_schemas: HashMap::new(),
            cached_cred_defs: HashMap::new(),
        })
    }

    pub fn create_credential_request(
        &self,
        cred_def: &CredentialDefinition,
        offer: &CredentialOffer,
    ) -> anyhow::Result<(CredentialRequest, CredentialRequestMetadata)> {
        Ok(prover::create_credential_request(
            Some("entropy"),
            None,
            cred_def,
            &self.link_secret,
            "my-secret",
            offer,
        )?)
    }

    pub fn process_credential(
        &mut self,
        mut credential: Credential,
        metadata: &CredentialRequestMetadata,
        cred_def: &CredentialDefinition,
    ) -> anyhow::Result<()> {
        prover::process_credential(&mut credential, metadata, &self.link_secret, cred_def, None)?;
        self.credentials.push(credential);
        Ok(())
    }

    pub fn create_presentation(
        &self,
        pres_req: &PresentationRequest,
        schemas: &HashMap<SchemaId, Schema>,
        cred_defs: &HashMap<CredentialDefinitionId, CredentialDefinition>,
    ) -> anyhow::Result<Presentation> {
        let mut presented_credentials = PresentCredentials::default();

        for credential in &self.credentials {
            let mut cred_builder = presented_credentials.add_credential(credential, None, None);

            for attr_name in ["name_attr", "age_attr"] {
                cred_builder.add_requested_attribute(attr_name, true);
            }
        }

        Ok(prover::create_presentation(
            pres_req,
            presented_credentials,
            None,
            &self.link_secret,
            schemas,
            cred_defs,
        )?)
    }

    #[allow(dead_code)]
    pub fn fetch_schema_from_vdr(&mut self, vdr: &Vdr, schema_id: &SchemaId) -> Option<&Schema> {
        if let Some(schema) = vdr.get_schema(schema_id) {
            self.cached_schemas.insert(schema_id.clone(), schema.clone());
            Some(self.cached_schemas.get(schema_id).unwrap())
        } else {
            None
        }
    }

    pub fn fetch_credential_definition_from_vdr(
        &mut self,
        vdr: &Vdr,
        cred_def_id: &CredentialDefinitionId,
    ) -> Option<&CredentialDefinition> {
        if let Some(cred_def) = vdr.get_credential_definition(cred_def_id) {
            if let Ok(cloned_cred_def) = cred_def.try_clone() {
                self.cached_cred_defs.insert(cred_def_id.clone(), cloned_cred_def);
                Some(self.cached_cred_defs.get(cred_def_id).unwrap())
            } else {
                None
            }
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn get_cached_schemas(&self) -> &HashMap<SchemaId, Schema> {
        &self.cached_schemas
    }

    pub fn get_cached_cred_defs(&self) -> &HashMap<CredentialDefinitionId, CredentialDefinition> {
        &self.cached_cred_defs
    }
}
