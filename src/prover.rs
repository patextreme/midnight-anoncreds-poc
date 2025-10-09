use std::collections::HashMap;

use anoncreds::data_types::cred_def::CredentialDefinitionId;
use anoncreds::data_types::rev_reg_def::RevocationRegistryDefinitionId;
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
}

impl Prover {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            link_secret: prover::create_link_secret()?,
            credentials: Vec::new(),
            credential_metadata: HashMap::new(),
            revocation_states: HashMap::new(),
        })
    }

    pub fn create_credential_request(
        &self,
        vdr: &Vdr,
        offer: &CredentialOffer,
    ) -> anyhow::Result<(CredentialRequest, CredentialRequestMetadata)> {
        let cred_def_id = &offer.cred_def_id;
        let cred_def = vdr
            .get_credential_definition(cred_def_id)
            .ok_or_else(|| anyhow::anyhow!("Credential definition not found: {}", cred_def_id))?
            .try_clone()?;

        Ok(prover::create_credential_request(
            Some("entropy"),
            None,
            &cred_def,
            &self.link_secret,
            "my-secret",
            offer,
        )?)
    }

    pub fn process_credential(
        &mut self,
        mut credential: Credential,
        metadata: &CredentialRequestMetadata,
        vdr: &Vdr,
        cred_def_id: &CredentialDefinitionId,
    ) -> anyhow::Result<()> {
        let cred_def = vdr
            .get_credential_definition(cred_def_id)
            .ok_or_else(|| anyhow::anyhow!("Credential definition not found: {}", cred_def_id))?
            .try_clone()?;

        prover::process_credential(&mut credential, metadata, &self.link_secret, &cred_def, None)?;
        self.credentials.push(credential);
        Ok(())
    }

    pub fn create_presentation(&self, pres_req: &PresentationRequest, vdr: &Vdr) -> anyhow::Result<Presentation> {
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
            &vdr.schemas,
            &vdr.cred_defs,
        )?)
    }
}
