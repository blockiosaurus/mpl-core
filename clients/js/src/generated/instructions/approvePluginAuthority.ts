/**
 * This code was AUTOGENERATED using the kinobi library.
 * Please DO NOT EDIT THIS FILE, instead use visitors
 * to add features, then rerun kinobi to update it.
 *
 * @see https://github.com/metaplex-foundation/kinobi
 */

import {
  Context,
  Pda,
  PublicKey,
  Signer,
  TransactionBuilder,
  transactionBuilder,
} from '@metaplex-foundation/umi';
import {
  Serializer,
  mapSerializer,
  struct,
  u8,
} from '@metaplex-foundation/umi/serializers';
import {
  ResolvedAccount,
  ResolvedAccountsWithIndices,
  getAccountMetasAndSigners,
} from '../shared';
import {
  Authority,
  AuthorityArgs,
  PluginType,
  PluginTypeArgs,
  getAuthoritySerializer,
  getPluginTypeSerializer,
} from '../types';

// Accounts.
export type ApprovePluginAuthorityInstructionAccounts = {
  /** The address of the asset */
  asset: PublicKey | Pda;
  /** The collection to which the asset belongs */
  collection?: PublicKey | Pda;
  /** The owner or delegate of the asset */
  authority?: Signer;
  /** The account paying for the storage fees */
  payer?: Signer;
  /** The system program */
  systemProgram?: PublicKey | Pda;
  /** The SPL Noop Program */
  logWrapper?: PublicKey | Pda;
};

// Data.
export type ApprovePluginAuthorityInstructionData = {
  discriminator: number;
  pluginType: PluginType;
  newAuthority: Authority;
};

export type ApprovePluginAuthorityInstructionDataArgs = {
  pluginType: PluginTypeArgs;
  newAuthority: AuthorityArgs;
};

export function getApprovePluginAuthorityInstructionDataSerializer(): Serializer<
  ApprovePluginAuthorityInstructionDataArgs,
  ApprovePluginAuthorityInstructionData
> {
  return mapSerializer<
    ApprovePluginAuthorityInstructionDataArgs,
    any,
    ApprovePluginAuthorityInstructionData
  >(
    struct<ApprovePluginAuthorityInstructionData>(
      [
        ['discriminator', u8()],
        ['pluginType', getPluginTypeSerializer()],
        ['newAuthority', getAuthoritySerializer()],
      ],
      { description: 'ApprovePluginAuthorityInstructionData' }
    ),
    (value) => ({ ...value, discriminator: 8 })
  ) as Serializer<
    ApprovePluginAuthorityInstructionDataArgs,
    ApprovePluginAuthorityInstructionData
  >;
}

// Args.
export type ApprovePluginAuthorityInstructionArgs =
  ApprovePluginAuthorityInstructionDataArgs;

// Instruction.
export function approvePluginAuthority(
  context: Pick<Context, 'identity' | 'programs'>,
  input: ApprovePluginAuthorityInstructionAccounts &
    ApprovePluginAuthorityInstructionArgs
): TransactionBuilder {
  // Program ID.
  const programId = context.programs.getPublicKey(
    'mplCore',
    'CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d'
  );

  // Accounts.
  const resolvedAccounts = {
    asset: {
      index: 0,
      isWritable: true as boolean,
      value: input.asset ?? null,
    },
    collection: {
      index: 1,
      isWritable: true as boolean,
      value: input.collection ?? null,
    },
    authority: {
      index: 2,
      isWritable: false as boolean,
      value: input.authority ?? null,
    },
    payer: {
      index: 3,
      isWritable: true as boolean,
      value: input.payer ?? null,
    },
    systemProgram: {
      index: 4,
      isWritable: false as boolean,
      value: input.systemProgram ?? null,
    },
    logWrapper: {
      index: 5,
      isWritable: false as boolean,
      value: input.logWrapper ?? null,
    },
  } satisfies ResolvedAccountsWithIndices;

  // Arguments.
  const resolvedArgs: ApprovePluginAuthorityInstructionArgs = { ...input };

  // Default values.
  if (!resolvedAccounts.authority.value) {
    resolvedAccounts.authority.value = context.identity;
  }
  if (!resolvedAccounts.systemProgram.value) {
    resolvedAccounts.systemProgram.value = context.programs.getPublicKey(
      'splSystem',
      '11111111111111111111111111111111'
    );
    resolvedAccounts.systemProgram.isWritable = false;
  }

  // Accounts in order.
  const orderedAccounts: ResolvedAccount[] = Object.values(
    resolvedAccounts
  ).sort((a, b) => a.index - b.index);

  // Keys and Signers.
  const [keys, signers] = getAccountMetasAndSigners(
    orderedAccounts,
    'programId',
    programId
  );

  // Data.
  const data = getApprovePluginAuthorityInstructionDataSerializer().serialize(
    resolvedArgs as ApprovePluginAuthorityInstructionDataArgs
  );

  // Bytes Created On Chain.
  const bytesCreatedOnChain = 0;

  return transactionBuilder([
    { instruction: { keys, programId, data }, signers, bytesCreatedOnChain },
  ]);
}
