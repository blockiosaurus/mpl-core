use std::collections::{BTreeMap, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{program_error::ProgramError, pubkey::Pubkey};

use crate::error::MplCoreError;

use crate::plugins::{
    abstain, Plugin, PluginValidation, PluginValidationContext, ValidationResult,
};
use crate::state::{DataBlob, Key};

/// The creator on an asset and whether or not they are verified.
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq, Hash)]
pub struct VerifiedCreatorsSignature {
    /// The address of the creator.
    pub address: Pubkey, // 32
    /// Whether or not the creator is verified.
    pub verified: bool, // 1
}

impl VerifiedCreatorsSignature {
    const BASE_LEN: usize = 32 // The address
    + 1; // The verified boolean
}

impl DataBlob for VerifiedCreatorsSignature {
    fn len(&self) -> usize {
        Self::BASE_LEN
    }
}

/// Structure for storing verified creators, often used in conjunction with the Royalties plugin
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, Eq, PartialEq)]
pub struct VerifiedCreators {
    /// A list of signatures
    pub signatures: Vec<VerifiedCreatorsSignature>, // 4 + len * VerifiedCreatorsSignature
}

impl VerifiedCreators {
    const BASE_LEN: usize = 4; // The signatures length
}

impl DataBlob for VerifiedCreators {
    fn len(&self) -> usize {
        Self::BASE_LEN + self.signatures.iter().map(|sig| sig.len()).sum::<usize>()
    }
}

struct SignatureChangeIndices {
    /// Indices of added signatures on new_verified_creators
    added: Vec<u8>,
    /// Indices of changed signatures on new_verified_creators
    changed: Vec<u8>,
    /// Indices of removed signatures on verified_creators
    removed: Vec<u8>,
}

fn calculate_signature_changes(
    new_verified_creators: &VerifiedCreators,
    verified_creators: Option<&VerifiedCreators>,
) -> Result<SignatureChangeIndices, ProgramError> {
    let existing_map = verified_creators.map_or_else(BTreeMap::new, |verified_creators| {
        verified_creators
            .signatures
            .iter()
            .map(|sig| (sig.address, sig))
            .collect::<BTreeMap<Pubkey, &VerifiedCreatorsSignature>>()
    });

    let new_signatures: HashSet<_> = new_verified_creators
        .signatures
        .iter()
        .map(|sig| sig.address)
        .collect();

    if new_verified_creators.signatures.len() != new_signatures.len() {
        // Ensure there are no duplicate signatures
        solana_program::msg!("Verified creators: Rejected");
        return Err(MplCoreError::InvalidPluginSetting.into());
    }

    let mut result = SignatureChangeIndices {
        added: Vec::new(),
        changed: Vec::new(),
        removed: Vec::new(),
    };

    for (i, sig) in new_verified_creators.signatures.iter().enumerate() {
        match existing_map.get(&sig.address) {
            Some(existing_sig) => {
                if existing_sig.verified != sig.verified {
                    result.changed.push(i as u8);
                }
            }
            None => {
                result.added.push(i as u8);
            }
        }
    }

    if let Some(verified_creators) = verified_creators {
        for (i, sig) in verified_creators.signatures.iter().enumerate() {
            if !new_signatures.contains(&sig.address) {
                result.removed.push(i as u8);
            }
        }
    }

    Ok(result)
}

fn validate_verified_creators_as_creator(
    new_verified_creators: &VerifiedCreators,
    verified_creators: &VerifiedCreators,
    authority: &Pubkey,
) -> Result<ValidationResult, ProgramError> {
    // Track any changes in verification status
    let changes = calculate_signature_changes(new_verified_creators, Some(verified_creators))?;

    if !changes.added.is_empty() || !changes.removed.is_empty() {
        // creators cannot add new allowable signatures or remove existing ones
        solana_program::msg!("Verified creators: Rejected");
        return Err(MplCoreError::MissingSigner.into());
    }

    for change in changes.changed.iter() {
        let sig = &new_verified_creators.signatures[*change as usize];
        if &sig.address != authority {
            // creators may only change their own verified status
            solana_program::msg!("Verified creators: Rejected");
            return Err(MplCoreError::MissingSigner.into());
        }
    }

    abstain!()
}

fn validate_verified_creators_as_plugin_authority(
    new_verified_creators: &VerifiedCreators,
    verified_creators: Option<&VerifiedCreators>,
    authority: &Pubkey,
) -> Result<ValidationResult, ProgramError> {
    // The plugin auth is allowed to: add/remove unverified creators, add self and sign for self.
    // The plugin auth cannot remove or unverify any existing creators other than self.
    // This is in line with legacy Token Metadata behaviour for verified creators

    let changes = calculate_signature_changes(new_verified_creators, verified_creators)?;

    for removal in changes.removed.iter() {
        let sig = &verified_creators.unwrap().signatures[*removal as usize];
        if sig.verified && &sig.address != authority {
            solana_program::msg!("Verified creators: Rejected");
            return Err(MplCoreError::InvalidPluginOperation.into());
        }
    }

    for change in changes.changed.iter() {
        let sig = &new_verified_creators.signatures[*change as usize];
        if &sig.address != authority {
            solana_program::msg!("Verified creators: Rejected");
            return Err(MplCoreError::InvalidPluginOperation.into());
        }
    }

    for addition in changes.added.iter() {
        let sig = &new_verified_creators.signatures[*addition as usize];
        if sig.verified && &sig.address != authority {
            solana_program::msg!("Verified creators: Rejected");
            return Err(MplCoreError::MissingSigner.into());
        }
    }

    abstain!()
}

/// Returns true when this plugin lives on a collection but the lifecycle target is an asset
/// (e.g. creating an asset in the collection, or adding a plugin to an asset in the collection).
/// In that case the collection's signatures are not the data being created, so they must not be
/// re-validated against the instruction signer: the signer would otherwise need to be the only
/// verified creator on the collection.
fn is_inherited_collection_check(ctx: &PluginValidationContext) -> bool {
    ctx.self_key == Key::CollectionV1 && ctx.asset_info.is_some()
}

impl PluginValidation for VerifiedCreators {
    fn validate_create(
        &self,
        ctx: &PluginValidationContext,
    ) -> Result<ValidationResult, ProgramError> {
        if is_inherited_collection_check(ctx) {
            // The asset is being created in a collection that carries this plugin. Only the
            // signatures on the asset itself (if any) are validated, via the asset's own plugin.
            return abstain!();
        }

        validate_verified_creators_as_plugin_authority(self, None, ctx.authority_info.key)
    }

    fn validate_add_plugin(
        &self,
        ctx: &PluginValidationContext,
    ) -> Result<ValidationResult, ProgramError> {
        match ctx.target_plugin {
            Some(Plugin::VerifiedCreators(_verified_creators)) => {
                if is_inherited_collection_check(ctx) {
                    // A VerifiedCreators plugin is being added to an asset in a collection that
                    // carries this plugin. The new plugin validates its own signatures.
                    return abstain!();
                }

                validate_verified_creators_as_plugin_authority(self, None, ctx.authority_info.key)
            }
            _ => abstain!(),
        }
    }

    fn validate_update_plugin(
        &self,
        ctx: &PluginValidationContext,
    ) -> Result<ValidationResult, ProgramError> {
        let resolved_authorities = ctx
            .resolved_authorities
            .ok_or(MplCoreError::InvalidAuthority)?;
        match ctx.target_plugin {
            Some(Plugin::VerifiedCreators(verified_creators)) => {
                if resolved_authorities.contains(ctx.self_authority) {
                    validate_verified_creators_as_plugin_authority(
                        verified_creators,
                        Some(self),
                        ctx.authority_info.key,
                    )?;
                    Ok(ValidationResult::Approved)
                } else {
                    validate_verified_creators_as_creator(
                        verified_creators,
                        self,
                        ctx.authority_info.key,
                    )?;
                    Ok(ValidationResult::Approved)
                }
            }
            _ => abstain!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Authority;
    use solana_program::account_info::AccountInfo;

    /// Builds a validation context for `plugin_key` (the account the plugin lives on) with an
    /// optional asset as the lifecycle target, signed by `authority_info`.
    fn validation_ctx<'a, 'b>(
        plugin_key: Key,
        asset_info: Option<&'a AccountInfo<'a>>,
        collection_info: Option<&'a AccountInfo<'a>>,
        self_authority: &'b Authority,
        authority_info: &'a AccountInfo<'a>,
    ) -> PluginValidationContext<'a, 'b> {
        PluginValidationContext {
            accounts: &[],
            asset_info,
            collection_info,
            self_key: plugin_key,
            self_authority,
            authority_info,
            resolved_authorities: None,
            new_owner: None,
            new_asset_authority: None,
            new_collection_authority: None,
            target_plugin: None,
            target_plugin_authority: None,
            target_external_plugin: None,
            target_external_plugin_authority: None,
        }
    }

    fn account_info<'a>(
        key: &'a Pubkey,
        lamports: &'a mut u64,
        data: &'a mut [u8],
        owner: &'a Pubkey,
    ) -> AccountInfo<'a> {
        AccountInfo::new(key, true, false, lamports, data, owner, false)
    }

    #[test]
    fn test_collection_plugin_abstains_when_creating_asset_in_collection() {
        // A verified creator on the collection that is not the signer.
        let creator = Pubkey::new_unique();
        let signer_key = Pubkey::new_unique();
        let asset_key = Pubkey::new_unique();
        let collection_key = Pubkey::new_unique();
        let owner = crate::ID;

        let plugin = VerifiedCreators {
            signatures: vec![VerifiedCreatorsSignature {
                address: creator,
                verified: true,
            }],
        };

        let mut signer_lamports = 0;
        let mut signer_data = [];
        let signer = account_info(&signer_key, &mut signer_lamports, &mut signer_data, &owner);
        let mut asset_lamports = 0;
        let mut asset_data = [];
        let asset = account_info(&asset_key, &mut asset_lamports, &mut asset_data, &owner);
        let mut collection_lamports = 0;
        let mut collection_data = [];
        let collection = account_info(
            &collection_key,
            &mut collection_lamports,
            &mut collection_data,
            &owner,
        );
        let self_authority = Authority::UpdateAuthority;

        // Creating an asset in a collection carrying this plugin: the collection plugin
        // must not re-validate its own signatures against the signer.
        let ctx = validation_ctx(
            Key::CollectionV1,
            Some(&asset),
            Some(&collection),
            &self_authority,
            &signer,
        );
        assert_eq!(plugin.validate_create(&ctx), Ok(ValidationResult::Pass));

        // Adding a VerifiedCreators plugin to an asset in such a collection: same thing.
        let target = Plugin::VerifiedCreators(VerifiedCreators { signatures: vec![] });
        let mut ctx = validation_ctx(
            Key::CollectionV1,
            Some(&asset),
            Some(&collection),
            &self_authority,
            &signer,
        );
        ctx.target_plugin = Some(&target);
        assert_eq!(plugin.validate_add_plugin(&ctx), Ok(ValidationResult::Pass));
    }

    #[test]
    fn test_self_check_still_requires_signer_for_verified_creators() {
        let creator = Pubkey::new_unique();
        let signer_key = Pubkey::new_unique();
        let asset_key = Pubkey::new_unique();
        let collection_key = Pubkey::new_unique();
        let owner = crate::ID;

        let plugin = VerifiedCreators {
            signatures: vec![VerifiedCreatorsSignature {
                address: creator,
                verified: true,
            }],
        };

        let mut signer_lamports = 0;
        let mut signer_data = [];
        let signer = account_info(&signer_key, &mut signer_lamports, &mut signer_data, &owner);
        let mut asset_lamports = 0;
        let mut asset_data = [];
        let asset = account_info(&asset_key, &mut asset_lamports, &mut asset_data, &owner);
        let mut collection_lamports = 0;
        let mut collection_data = [];
        let collection = account_info(
            &collection_key,
            &mut collection_lamports,
            &mut collection_data,
            &owner,
        );
        let self_authority = Authority::UpdateAuthority;

        // Creating the collection itself with this plugin: the signer must be the creator.
        let ctx = validation_ctx(
            Key::CollectionV1,
            None,
            Some(&collection),
            &self_authority,
            &signer,
        );
        assert_eq!(
            plugin.validate_create(&ctx),
            Err(MplCoreError::MissingSigner.into())
        );

        // Creating an asset with this plugin on the asset itself: same requirement, whether
        // or not the asset is in a collection.
        let ctx = validation_ctx(
            Key::AssetV1,
            Some(&asset),
            Some(&collection),
            &self_authority,
            &signer,
        );
        assert_eq!(
            plugin.validate_create(&ctx),
            Err(MplCoreError::MissingSigner.into())
        );

        // Adding this plugin to an asset: same requirement.
        let target = Plugin::VerifiedCreators(plugin.clone());
        let mut ctx = validation_ctx(
            Key::AssetV1,
            Some(&asset),
            Some(&collection),
            &self_authority,
            &signer,
        );
        ctx.target_plugin = Some(&target);
        assert_eq!(
            plugin.validate_add_plugin(&ctx),
            Err(MplCoreError::MissingSigner.into())
        );
    }

    #[test]
    fn test_verified_creators_signature_len() {
        let verified_creators_signature = VerifiedCreatorsSignature {
            address: Pubkey::default(),
            verified: false,
        };
        let serialized = borsh::to_vec(&verified_creators_signature).unwrap();
        assert_eq!(serialized.len(), verified_creators_signature.len());
    }

    #[test]
    fn test_verified_creators_default_len() {
        let verified_creators = VerifiedCreators { signatures: vec![] };
        let serialized = borsh::to_vec(&verified_creators).unwrap();
        assert_eq!(serialized.len(), verified_creators.len());
    }

    #[test]
    fn test_verified_creators_len() {
        let verified_creators = VerifiedCreators {
            signatures: vec![
                VerifiedCreatorsSignature {
                    address: Pubkey::default(),
                    verified: false,
                },
                VerifiedCreatorsSignature {
                    address: Pubkey::default(),
                    verified: true,
                },
            ],
        };
        let serialized = borsh::to_vec(&verified_creators).unwrap();
        assert_eq!(serialized.len(), verified_creators.len());
    }
}
