use std::collections::HashMap;

use anoncreds::data_types::cred_def::{CredentialDefinition, CredentialDefinitionId};
use anoncreds::data_types::issuer_id::IssuerId;
use anoncreds::data_types::rev_reg_def::{RevocationRegistryDefinition, RevocationRegistryDefinitionId};
use anoncreds::data_types::schema::{Schema, SchemaId};
use anoncreds::issuer;
use anoncreds::tails::TailsFileWriter;
use anoncreds::types::*;

use crate::vdr::Vdr;

pub struct Issuer {
    pub id: IssuerId,
    pub schemas: HashMap<SchemaId, Schema>,
    pub cred_defs: HashMap<CredentialDefinitionId, (CredentialDefinition, CredentialDefinitionPrivate)>,
    pub correctness_proofs: HashMap<CredentialDefinitionId, CredentialKeyCorrectnessProof>,
    pub rev_reg_defs:
        HashMap<RevocationRegistryDefinitionId, (RevocationRegistryDefinition, RevocationRegistryDefinitionPrivate)>,
    pub rev_status_lists: HashMap<RevocationRegistryDefinitionId, RevocationStatusList>,
    pub tails_writer: TailsFileWriter,
}

impl Issuer {
    pub fn new<T: Into<String>>(id: T) -> anyhow::Result<Self> {
        let issuer_id = IssuerId::new(id)?;
        Ok(Self {
            id: issuer_id,
            schemas: HashMap::new(),
            cred_defs: HashMap::new(),
            correctness_proofs: HashMap::new(),
            rev_reg_defs: HashMap::new(),
            rev_status_lists: HashMap::new(),
            tails_writer: TailsFileWriter::new(None),
        })
    }

    pub fn create_schema(&mut self, name: &str, version: &str, attrs: &[&str]) -> anyhow::Result<SchemaId> {
        let schema_id = SchemaId::new(format!("vdr://schemas/{}?drf=midnight", name))?;
        let schema = issuer::create_schema(name, version, self.id.clone(), attrs.into())?;
        self.schemas.insert(schema_id.clone(), schema);
        Ok(schema_id)
    }

    pub fn create_schema_and_publish(
        &mut self,
        vdr: &mut Vdr,
        name: &str,
        version: &str,
        attrs: &[&str],
    ) -> anyhow::Result<SchemaId> {
        let schema_id = self.create_schema(name, version, attrs)?;
        let schema = self.schemas.get(&schema_id).unwrap().clone();
        vdr.publish_schema(schema_id.clone(), schema);
        Ok(schema_id)
    }

    pub fn create_credential_definition(
        &mut self,
        schema_id: &SchemaId,
        tag: &str,
        support_revocation: bool,
    ) -> anyhow::Result<CredentialDefinitionId> {
        let schema = self
            .schemas
            .get(schema_id)
            .ok_or_else(|| anyhow::anyhow!("Schema not found"))?;
        let cred_def_id = CredentialDefinitionId::new(format!(
            "vdr://credential-definitions/{}-{}?drf=midnight",
            schema_id, tag
        ))?;

        let (cred_def, cred_def_priv, cred_def_correctness_proof) = issuer::create_credential_definition(
            schema_id.clone(),
            schema,
            self.id.clone(),
            tag,
            SignatureType::CL,
            CredentialDefinitionConfig { support_revocation },
        )?;

        self.cred_defs
            .insert(cred_def_id.clone(), (cred_def.try_clone()?, cred_def_priv));
        self.correctness_proofs
            .insert(cred_def_id.clone(), cred_def_correctness_proof);
        Ok(cred_def_id)
    }

    pub fn create_credential_definition_and_publish(
        &mut self,
        vdr: &mut Vdr,
        schema_id: &SchemaId,
        tag: &str,
        support_revocation: bool,
    ) -> anyhow::Result<CredentialDefinitionId> {
        let cred_def_id = self.create_credential_definition(schema_id, tag, support_revocation)?;
        let (cred_def, _) = self.cred_defs.get(&cred_def_id).unwrap();
        vdr.publish_credential_definition(cred_def_id.clone(), cred_def.try_clone()?);
        Ok(cred_def_id)
    }

    pub fn create_revocation_registry(
        &mut self,
        cred_def_id: &CredentialDefinitionId,
        tag: &str,
        max_credentials: u32,
    ) -> anyhow::Result<RevocationRegistryDefinitionId> {
        let (cred_def, _) = self
            .cred_defs
            .get(cred_def_id)
            .ok_or_else(|| anyhow::anyhow!("Credential definition not found"))?;
        let rev_reg_def_id = RevocationRegistryDefinitionId::new(format!(
            "vdr://revocation-registry-definitions/{}-{}",
            cred_def_id, tag
        ))?;

        let (rev_reg_def, rev_reg_def_priv) = issuer::create_revocation_registry_def(
            cred_def,
            cred_def_id.clone(),
            tag,
            RegistryType::CL_ACCUM,
            max_credentials,
            &mut self.tails_writer,
        )?;

        self.rev_reg_defs
            .insert(rev_reg_def_id.clone(), (rev_reg_def.clone(), rev_reg_def_priv));
        Ok(rev_reg_def_id)
    }

    pub fn create_revocation_registry_and_publish(
        &mut self,
        vdr: &mut Vdr,
        cred_def_id: &CredentialDefinitionId,
        tag: &str,
        max_credentials: u32,
    ) -> anyhow::Result<RevocationRegistryDefinitionId> {
        let rev_reg_def_id = self.create_revocation_registry(cred_def_id, tag, max_credentials)?;
        let (rev_reg_def, _) = self.rev_reg_defs.get(&rev_reg_def_id).unwrap();
        vdr.publish_revocation_registry_definition(rev_reg_def_id.clone(), rev_reg_def.clone());
        Ok(rev_reg_def_id)
    }

    pub fn create_credential_offer(
        &self,
        schema_id: &SchemaId,
        cred_def_id: &CredentialDefinitionId,
    ) -> anyhow::Result<CredentialOffer> {
        let correctness_proof = self
            .correctness_proofs
            .get(cred_def_id)
            .ok_or_else(|| anyhow::anyhow!("Correctness proof not found"))?;
        Ok(issuer::create_credential_offer(
            schema_id.clone(),
            cred_def_id.clone(),
            correctness_proof,
        )?)
    }

    pub fn issue_credential(
        &mut self,
        offer: &CredentialOffer,
        request: &CredentialRequest,
        values: MakeCredentialValues,
    ) -> anyhow::Result<Credential> {
        let cred_def_id = &offer.cred_def_id;
        let (cred_def, cred_def_priv) = self
            .cred_defs
            .get(cred_def_id)
            .ok_or_else(|| anyhow::anyhow!("Credential definition not found"))?;
        Ok(issuer::create_credential(
            cred_def,
            cred_def_priv,
            offer,
            request,
            values.into(),
            None,
        )?)
    }

    #[allow(dead_code)]
    pub fn get_credential_definition(&self, cred_def_id: &CredentialDefinitionId) -> Option<&CredentialDefinition> {
        self.cred_defs.get(cred_def_id).map(|(cred_def, _)| cred_def)
    }

    pub fn create_revocation_status_list(
        &mut self,
        rev_reg_def_id: &RevocationRegistryDefinitionId,
        timestamp: Option<u64>,
    ) -> anyhow::Result<RevocationStatusList> {
        let (rev_reg_def, rev_reg_def_priv) = self
            .rev_reg_defs
            .get(rev_reg_def_id)
            .ok_or_else(|| anyhow::anyhow!("Revocation registry definition not found"))?;
        let (cred_def, _) = self
            .cred_defs
            .get(&rev_reg_def.cred_def_id)
            .ok_or_else(|| anyhow::anyhow!("Credential definition not found"))?;

        let rev_list = issuer::create_revocation_status_list(
            cred_def,
            rev_reg_def_id.clone(),
            rev_reg_def,
            rev_reg_def_priv,
            true,
            timestamp,
        )?;

        self.rev_status_lists.insert(rev_reg_def_id.clone(), rev_list.clone());
        Ok(rev_list)
    }

    pub fn publish_revocation_status_list(
        &mut self,
        vdr: &mut Vdr,
        rev_reg_def_id: &RevocationRegistryDefinitionId,
        timestamp: Option<u64>,
    ) -> anyhow::Result<()> {
        let rev_list = self.create_revocation_status_list(rev_reg_def_id, timestamp)?;
        vdr.publish_revocation_status_list(rev_reg_def_id.clone(), rev_list);
        Ok(())
    }
}
